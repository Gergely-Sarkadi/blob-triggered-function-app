import hashlib
import logging
import os
import vt

import azure.functions as func
from azure.identity import ManagedIdentityCredential
from azure.storage.blob import BlobServiceClient
from urllib.parse import urlparse


def get_blob_service_client_token_credential(account_url):
    '''Get a token for an account with managed identity.'''
    credential = ManagedIdentityCredential()
    return BlobServiceClient(account_url, credential=credential)

def parse_url(blob_url):
    '''Parse out and return the container name and the file name from a blob url.'''
    parsed_url = urlparse(blob_url)
    container_name = parsed_url.path.split('/')[1]
    blob_name = '/'.join(parsed_url.path.split('/')[2:])
    return (container_name, blob_name)

def parse_filename(filename):
    '''Parse out and return the name and extension of a file. Like: 'hello.txt' -> (hello, txt)'''
    split_name = filename.split('.')
    name = '.'.join(split_name[:-1])
    extension = split_name[-1] if len(split_name) > 1 else ''
    return (name, extension)

def check_file_hash_for_viruses(md5_hash):
    '''
    Send the checksum of the blob to the VirusTotal API for virus checking.
    Set the API key as an environmental variable of the Function App.
    '''
    client = vt.Client(os.environ['VIRUSTOTAL_API_KEY'])
    try:
        file = client.get_object(f'/files/{md5_hash}')
        logging.info(f'File analysis: {file.last_analysis_stats}')
        return file.last_analysis_stats['malicious'] == 0
    except vt.APIError:
        logging.info(f'Hash not found in the virus database: {md5_hash}')
        return True

def main(msg: func.QueueMessage) -> None:
    # Download and process blob
    source_blob_url = msg.get_json()['data']['blobUrl']
    # source_blob_service_client = get_blob_service_client_token_credential("https://<your source service accounts name>.blob.core.windows.net")
    source_blob_service_client = BlobServiceClient.from_connection_string(os.environ['SOURCE_STORAGE_ACCOUNT_CONN_STRING'])

    container_name, source_blob_name = parse_url(source_blob_url)
    source_blob_client = source_blob_service_client.get_blob_client(container=container_name, blob=source_blob_name)
    source_blob_data = source_blob_client.download_blob().readall()
    checksum = hashlib.md5(source_blob_data).hexdigest()
    logging.info(f'Blob url: {source_blob_url} \n'
                 f'Blob checksum: {checksum}')
    
    if check_file_hash_for_viruses(checksum):
        logging.info(f'The uploaded file is safe. Upload it to the second Storage Account.')

        # Upload blob
        # target_blob_service_client = get_blob_service_client_token_credential("https://<your target service accounts name>.blob.core.windows.net")
        target_blob_service_client = BlobServiceClient.from_connection_string(os.environ['TARGET_STORAGE_ACCOUNT_CONN_STRING'])

        # Check if a container exists on the target with the same name as the source container, create it if necessary
        target_container_client = target_blob_service_client.get_container_client(container_name)
        if not target_container_client.exists():
            target_container_client.create_container()

        # Put the checksum of the blob in its name and upload.
        blob_name, extension = parse_filename(source_blob_name)
        target_blob_name = f'{blob_name}.{checksum}.{extension}'
        logging.info(f'Target blob name: {target_blob_name}')
        target_blob_client = target_blob_service_client.get_blob_client(container=container_name, blob=target_blob_name)
        target_blob_client.upload_blob(source_blob_data, overwrite=True)

    else:
        logging.warning(f'The uploaded file is infected! It won\'t be uploaded to the second Storage Account, and will be deleted.')

        # TODO necessary steps if a file is infected (send an alarm, block the user, put the file in quaranteen, etc.)

    # Delete the original blob
    source_blob_client.delete_blob()
