from pathlib import Path

from flask import current_app


def finalize_upload(local_path: Path, object_key: str):
    if not current_app.config.get('ENABLE_MINIO'):
        return 'local', None
    from minio import Minio
    client=Minio(current_app.config['MINIO_ENDPOINT'],access_key=current_app.config['MINIO_ACCESS_KEY'],secret_key=current_app.config['MINIO_SECRET_KEY'],secure=current_app.config['MINIO_SECURE'])
    bucket=current_app.config['MINIO_BUCKET']
    if not client.bucket_exists(bucket): client.make_bucket(bucket)
    client.fput_object(bucket,object_key,str(local_path))
    return 'minio',object_key
