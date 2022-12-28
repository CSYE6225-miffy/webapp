import subprocess

from utils.utils import load_app_config


def main():
    app_config = load_app_config()
    try:
        print('starting the app')
        app_proc = subprocess.Popen(["./start"])
        try:
            app_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        print('verify app status')
        assert app_proc.returncode is None, "app is not running"
        cmd = ["curl", f"http://localhost:{app_config['port']}/ping"]
        print(cmd)
        response = subprocess.check_output(cmd)
        if response.decode() == 'pong':
            print('GOOD')
        else:
            raise Exception('BAD')
    finally:
        if app_proc.returncode is None:
            subprocess.check_call(['pkill', '-P', str(app_proc.pid)])


if __name__ == "__main__":
    main()
