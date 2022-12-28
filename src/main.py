import datetime
import hashlib
import json
import os
import re
import textwrap
import typing as t
import uuid

import bcrypt
import flask
import statsd as statsd
from flask import request, jsonify, make_response
from flask_httpauth import HTTPBasicAuth
from werkzeug.datastructures import FileStorage

from executor import executor
from utils.utils import load_app_config
from utils.logger import Logger
import verify_operation

app = flask.Flask(__name__)
auth = HTTPBasicAuth()
log = Logger("CSYE6225.log")
metric_counter = statsd.client.StatsClient('localhost', 8125)


@auth.verify_password
def get_password_auth(username: str, password: str) -> bool:
    sql = f'select id, username, password from webapp where username="{username}";'
    result = executor.db.execute_and_get_result(sql)
    is_verified = len(result) and bcrypt.checkpw(password.encode(), result[0]['password'].encode())
    return is_verified


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'Response': 'Unauthorized'}), 401)


# def token_required(f: t.Callable[..., str]):
#     @wraps(f)
#     def decorator(*args, **kwargs) -> str:
#         token = None
#         if TOKEN_HEADER_KEY in request.headers:
#             token = request.headers[TOKEN_HEADER_KEY]
#         if not token:
#             return jsonify({'message': 'a valid token is missing'})
#         try:
#             data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
#             sql = 'select 1 from webapp where id="{}";'.format(data['id'])
#             result = executor.db.execute_and_get_result(sql)
#             if len(result) == 0:
#                 raise jwt.InvalidTokenError()
#         except:
#             return jsonify({'message': 'token is invalid'})
#
#         return f(*args, **kwargs)
#
#     return decorator


# @app.route('/login', methods=['POST'])
# def login_user():
#     auth = request.json
#     if not auth or not auth['username'] or not auth['password']:
#         return make_response('could not verify', 401, {'Authentication': 'login required"'})
#
#     # user = Users.query.filter_by(name=auth.username).first()
#     sql = "select id, username, password from webapp where username=\"%s\";" % auth['username']
#     result = executor.db.execute_and_get_result(sql)
#     if len(result) and bcrypt.checkpw(auth['password'].encode(), result[0]['password'].encode()):
#         token = jwt.encode(
#             {'id': result[0]['id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45)},
#             app.config['SECRET_KEY'], "HS256"
#         )
#
#         return jsonify({'token': token})
#
#     return make_response('could not verify', 401, {'Authentication': '"login required"'})


@app.route('/v1/account/<account_id>', methods=['GET'])
@auth.login_required
def get_user_info(account_id):
    log.logger.info("[GET]/v1/account/<account_id> - Get account information has been requested!")
    metric_counter.incr("get_account_information")

    # Check user id consistency
    username = auth.username()
    uid = get_user_id_from_username(username)
    if uid != account_id:
        return flask.jsonify({"Response": "Unauthorized. You can only access your account"}), 401

    # Check if Email address is verified
    sql = f'SELECT * FROM webapp where id="{account_id}";'
    result = executor.db.execute_and_get_result(sql)
    if result:
        data = result[0]
        if not data["verified"]:
            return flask.jsonify({"Response": "Unauthorized"}), 401
        log.logger.info("[GET]/v1/account/<account_id> - User's account has been authorized.")
        resp_json = {
            "id": data['id'],
            "first_name": data['first_name'],
            "last_name": data['last_name'],
            "username": data['username'],
            "account_created": str(data['account_created']),
            "account_updated": str(data['account_updated'])
        }
        resp = flask.jsonify(resp_json)
        resp.headers["Content-Type"] = "application / json"
        return resp, 200
    else:
        return flask.jsonify({"Response": "Bad request"}), 400


@app.route('/v1/account/<account_id>', methods=['PUT'])
@auth.login_required
def update_user_info(account_id):
    log.logger.info("[UPDATE]/v1/account/<account_id> - Update account information has been requested!")
    metric_counter.incr("update_account_information")

    # Check user id consistency
    username = auth.username()
    uid = get_user_id_from_username(username)
    if uid != account_id:
        return flask.jsonify({"Response": "Unauthorized. You can only access your account"}), 401

    # Check if Email address is verified
    sql = f'SELECT * FROM webapp where id="{account_id}";'
    result = executor.db.execute_and_get_result(sql)
    if result:
        data = result[0]
        if not data["verified"]:
            return flask.jsonify({"Response": "Unauthorized"}), 401
        log.logger.info("[UPDATE]/v1/account/<account_id> - User's account has been authorized.")

    try:
        json_data = json.loads(request.data)
        if len(json_data) == 0:
            return flask.jsonify({"Response": "Bad request"}), 400

        if "id" in json_data or "account_created" in json_data or "account_updated" in json_data:
            return flask.jsonify({"Response": "Bad request"}), 400

        to_update = {**json_data}
        if 'password' in to_update:
            to_update['password'] = gen_password_hash(to_update['password'])
        sql = 'update webapp set {} where id="{}"'.format(
            ','.join([f'{k}="{v}"' for k, v in to_update.items()]), account_id
        )
        print(sql)
        if executor.db.execute(sql):
            return "User updated", 204
        else:
            return flask.jsonify({"Response": "Bad request"}), 400
    except json.decoder.JSONDecodeError:
        return flask.jsonify({"Response": "Bad request"}), 400


@app.route('/healthz', methods=['GET'])
def health():
    log.logger.info("[GET]/healthz - Get healthz has been requested!")
    metric_counter.incr("get_healthz_check")
    return "OK", 200


@app.route('/ping', methods=['GET'])
def ping():
    log.logger.info("[GET]/ping - Get ping has been requested!")
    metric_counter.incr("get_ping_check")
    return "pong", 200


@app.route('/v1/account', methods=['POST'])
def create_user():
    log.logger.info("[POST]/v1/account - Post account information has been requested!")
    metric_counter.incr("post_account_information")

    try:
        json_data = json.loads(request.data)
        first_name = json_data["first_name"]
        last_name = json_data["last_name"]
        password = json_data["password"]
        username = json_data["username"]
        account_created = str(datetime.datetime.now())
        account_updated = account_created

        if check_username_exists(username):
            return flask.jsonify({"Response": "Bad request"}), 400

        reg_pattern = re.compile(r"^[\w-]+(\.[\w-]+)*@[\w-]+(\.[\w-]+)+$")
        if reg_pattern.match(username) is None:
            return flask.jsonify({"Response": "Bad request"}), 400

        user_id = hashlib.md5(account_created.encode('utf-8')).hexdigest()
        hash_pswd = gen_password_hash(password)

        sql = textwrap.dedent(
            f"""\
            INSERT INTO webapp
            (id, username, password, first_name, last_name, account_created, account_updated) 
            VALUES ("{user_id}", "{username}", "{hash_pswd}", "{first_name}", "{last_name}", "{account_created}", 
            "{account_updated}");
            """
        )
        print(sql)
        executor.db.execute(sql)
        sql = textwrap.dedent(
            f"""\
            SELECT id, username, first_name, last_name, account_created, account_updated, verified
            from webapp where id="{user_id}";
            """
        )
        result = executor.db.execute_and_get_result(sql)
        if result:
            data = result[0]
            # if not data["verified"]:
            #     return flask.jsonify({"Response": "Unauthorized"}), 401
            resp_json = {
                "id": data['id'],
                "first_name": data['first_name'],
                "last_name": data['last_name'],
                "username": data['username'],
                "account_created": str(data['account_created']),
                "account_updated": str(data['account_updated'])
            }
            resp = flask.jsonify(resp_json)
            resp.headers["Content-Type"] = "application / json"

            # Start performing validation
            log.logger.info("[POST]/v1/account - Start performing validation!")
            if not verify_operation.send_validation(email_address=username):
                return flask.jsonify({"Response": "Bad validation request"}), 400

            return resp, 201
        else:
            return flask.jsonify({"Response": "Bad request no result"}), 400

    except KeyError or json.decoder.JSONDecodeError:
        # return "Missing required field: %s" % e, 400
        return flask.jsonify({"Response": "Bad request keyerror"}), 400


# Get list of all documents uploaded
@app.route('/v1/documents', methods=['GET'])
@auth.login_required
def get_document():
    log.logger.info("[GET]/v1/documents - Get documents information has been requested!")
    metric_counter.incr("get_list_of_documents_information")

    # Check if Email address is verified
    username = auth.username()
    uid = get_user_id_from_username(username)
    sql = f'SELECT * FROM webapp where id="{uid}";'
    result = executor.db.execute_and_get_result(sql)
    if result:
        data = result[0]
        if not data["verified"]:
            return flask.jsonify({"Response": "Unauthorized"}), 401
    log.logger.info("[GET]/v1/documents - User's account has been authorized.")

    sql = textwrap.dedent(
        f'''
            SELECT * FROM documents where id="{uid}";
            '''
    )
    if result := executor.db.execute_and_get_result(sql):
        return result, 200
    else:
        return flask.jsonify({"Response": "Bad request"}), 400


# Upload documents. If one of documents upload failed, skip them.
@app.route('/v1/documents', methods=['POST'])
@auth.login_required
def upload_document():
    log.logger.info("[POST]/v1/documents - Post documents has been requested!")
    metric_counter.incr("upload_documents_information")

    # Check if Email address is verified
    username = auth.username()
    uid = get_user_id_from_username(username)
    sql = f'SELECT * FROM webapp where id="{uid}";'
    result = executor.db.execute_and_get_result(sql)
    if result:
        data = result[0]
        if not data["verified"]:
            return flask.jsonify({"Response": "Unauthorized"}), 401
    log.logger.info("[POST]/v1/documents - User's account has been authorized.")

    files = request.files
    results = []
    for filename, file in files.items():
        result = upload_file(uid, filename, file)
        if result:
            results.append(result)

    if not results:
        return flask.jsonify({"Response": "Bad request"}), 400

    resp = flask.jsonify(results)
    resp.headers["Content-Type"] = "application / json"
    return resp, 201


# Get document detail
@app.route('/v1/documents/<doc_id>', methods=['GET'])
@auth.login_required
def get_document_detail(doc_id):
    log.logger.info("[GET]/v1/documents/<doc_id> - Get document information has been requested!")
    metric_counter.incr("get_document_detail")

    # Check if Email address is verified
    username = auth.username()
    uid = get_user_id_from_username(username)
    sql = f'SELECT * FROM webapp where id="{uid}";'
    result = executor.db.execute_and_get_result(sql)
    if result:
        data = result[0]
        if not data["verified"]:
            return flask.jsonify({"Response": "Unauthorized"}), 401
    log.logger.info("[GET]/v1/documents/<doc_id> - User's account has been authorized.")

    sql = textwrap.dedent(
        f'''
            SELECT * FROM documents 
            WHERE documents.doc_id="{doc_id}";
               '''
    )
    if result := executor.db.execute_and_get_result(sql):
        return result, 200
    else:
        return flask.jsonify({"Response": "Bad request"}), 400


# Users can delete only their own documents. The document must be deleted from the S3 bucket.
@app.route('/v1/documents/<doc_id>', methods=['DELETE'])
@auth.login_required
def delete_document(doc_id):
    log.logger.info("[DEL]/v1/documents/<doc_id> - Delete document information has been requested!")
    metric_counter.incr("delete_document_information")
    username = auth.username()
    uid = get_user_id_from_username(username)

    # Check if Email address is verified
    sql = f'SELECT * FROM webapp where id="{uid}";'
    result = executor.db.execute_and_get_result(sql)
    if result:
        data = result[0]
        if not data["verified"]:
            return flask.jsonify({"Response": "Unauthorized"}), 401
    log.logger.info("[DEL]/v1/documents/<doc_id> - User's account has been authorized.")

    if does_file_exist(uid, doc_id):
        sql = textwrap.dedent(
            f"""
            DELETE FROM documents WHERE uid = "{uid}" and doc_id = "{doc_id}";
            """
        )
        if executor.db.execute(sql) and executor.s3.delete(key=doc_id):
            return flask.jsonify({"Response": "No Content"}), 204
        else:
            return flask.jsonify({"Response": "Bad Request"}), 400
    else:
        return flask.jsonify({"Response": "Not found"}), 404


def gen_password_hash(pswd: str) -> str:
    return bcrypt.hashpw(pswd.encode('utf-8'), bcrypt.gensalt()).decode()


def check_username_exists(username: str) -> bool:
    sql = f'SELECT username FROM webapp where username="{username}";'
    result = executor.db.execute_and_get_result(sql)
    return result


def get_user_id_from_username(username: str) -> str:
    sql = f'SELECT id FROM webapp where username="{username}";'
    result = executor.db.execute_and_get_result(sql)
    assert len(result), f'username "{username}" is not found'
    uid = result[0]['id']
    return uid


def does_file_exist(uid: str, doc_id: str) -> bool:
    sql = textwrap.dedent(
        f'''
        SELECT 1 FROM documents 
        WHERE documents.uid="{uid}" and documents.doc_id="{doc_id}";
        '''
    )
    result = executor.db.execute_and_get_result(sql)
    return bool(result)


def upload_file_to_s3(doc_id: str, file: FileStorage) -> t.Optional[str]:
    if executor.s3.post(key=doc_id, data=file):
        s3_bucket_path = os.path.join(executor.s3.bucket_name, doc_id)
        return s3_bucket_path
    return None


def create_file_metadata(uid, doc_id, filename, s3_bucket_path) -> t.Dict[str, t.Any]:
    date_created = str(datetime.datetime.now())
    sql = textwrap.dedent(
        f"""
        INSERT INTO documents 
        (doc_id, uid, filename, s3_bucket_path, date_created)
        VALUES ("{doc_id}", "{uid}", "{filename}", "{s3_bucket_path}", "{date_created}");
        """
    )
    executor.db.execute(sql)
    result = {
        "name": filename,
        "doc_id": doc_id,
        "s3_bucket_path": s3_bucket_path,
        "date_created": date_created,
        "user_id": uid
    }
    return result


def upload_file(uid: str, filename: str, file: FileStorage) -> t.Dict[str, t.Any]:
    doc_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{uid}::{filename}"))
    if does_file_exist(uid, doc_id):
        return {}  # skip

    if s3_bucket_path := upload_file_to_s3(doc_id, file):
        metadata = create_file_metadata(uid, doc_id, filename, s3_bucket_path)
        return metadata
    return {}


@app.route('/v1/verifyUserEmail', methods=['GET'])
def verify_user_email():
    dic = request.args
    try:
        email = dic["email"]
        token = dic["token"]
        sql = f'SELECT * FROM webapp where username="{email}";'
        result = executor.db.execute_and_get_result(sql)
        if result:
            if verify_operation.verify_token(email, token):
                sql = f'UPDATE webapp SET verified=TRUE where username="{email}";'
                print(sql)
                executor.db.execute(sql)
                return flask.jsonify({"Response": "Your account has been verified"}), 200
            else:
                return flask.jsonify({"Response": "Token is expired"}), 200
        else:
            return flask.jsonify({"Response": "Bad Request"}), 400

    except KeyError or Exception:
        return flask.jsonify({"Response": "Bad Request"}), 400


if __name__ == '__main__':
    # app.config['SECRET_KEY'] = 'secret'
    # TOKEN_HEADER_KEY = 'x-access-tokens'
    app_config = load_app_config()
    log.logger.info("Starting webapp application")
    app.run(host=app_config['host'], port=app_config['port'], debug=False, processes=True)