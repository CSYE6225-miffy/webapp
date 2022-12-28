import boto3
import typing as t
from utils.utils import get_root_dir
from os import path


def _read_file(path: str) -> str:
    with open(path) as f:
        content = f.read()
    return content.strip()


class S3:
    def __init__(self):
        root_dir = get_root_dir()
        self.s3 = boto3.resource(service_name='s3')
        try:
            self.bucket_name = _read_file(path.join(root_dir, "webappConfig/bucket_name.txt"))
        except Exception as e:
            raise e
            return False

    def post(self, key: str, data: t.Any) -> bool:
        try:
            self.s3.Bucket(self.bucket_name).put_object(Key=key, Body=data)
            return True
        except Exception as e:
            raise e
            return False

    def get(self, key: str) -> t.Any:
        try:
            obj = self.s3.Object(bucket_name=self.bucket_name, key=key).get()
            return obj
        except Exception as e:
            raise e
            return None

    def delete(self, key: str) -> bool:
        _dic = {
            'Objects': [{'Key': key}],
            'Quiet': True | False
        }
        try:
            self.s3.Bucket(self.bucket_name).delete_objects(Delete=_dic)
            return True
        except Exception as e:
            raise e
            return False
