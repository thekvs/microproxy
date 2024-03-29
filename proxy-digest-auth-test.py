import sys
import urllib.request, urllib.error, urllib.parse
import argparse


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", type=str, metavar="PROXY", required=True,
                        help="address of a proxy server")
    parser.add_argument("--user", type=str, metavar="USER", required=True,
                        help="proxy user")
    parser.add_argument("--password", type=str, metavar="PASSWORD", required=True,
                        help="proxt user's password")
    parser.add_argument("--url", type=str, metavar="URL", required=True,
                        help="URL to access")

    args = parser.parse_args()

    return args


def main():
    args = parse_args()

    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, args.url, args.user, args.password)
    auth_handler = urllib.request.ProxyDigestAuthHandler(password_manager)
    proxy_support = urllib.request.ProxyHandler({"http": args.proxy})
    opener = urllib.request.build_opener(proxy_support, auth_handler)
    urllib.request.install_opener(opener)
    handle = urllib.request.urlopen(args.url)
    page = handle.read()

    print((page), end=' ')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(exc)
        sys.exit(-1)
