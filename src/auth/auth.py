import os.path as path


def _get_absolute_file_path(rel_path: str):
    p = path.join(path.dirname(__file__), rel_path)
    return p


ROOT_KEY_PATH = _get_absolute_file_path("./root_key.pem")
ROOT_CERT_PATH = _get_absolute_file_path("./root_certificate.pem")

CLIENT_KEY_PATH = _get_absolute_file_path("./client_key.pem")
CLIENT_CERT_PATH = _get_absolute_file_path("./client_certificate.pem")

SERVER_KEY_PATH = _get_absolute_file_path("./server_key.pem")
SERVER_CERT_PATH = _get_absolute_file_path("./server_certificate.pem")
