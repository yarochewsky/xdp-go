#!/usr/bin/env python3

from datetime import datetime, timezone
import argparse

def main(git_hash, git_date):
    parsed = datetime.strptime(git_date, '%c %z')
    utc_hash = parsed.astimezone(timezone.utc)
    stamp = utc_hash.strftime('%Y%m%d%H%M%S')
    print(f'v0.0.0-{stamp}-{git_hash[:12]}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='create a go.mod pseudo version tag')
    parser.add_argument('git_hash', help='git commit hash')
    parser.add_argument('git_date', help='git commit timestamp')
    args = parser.parse_args()
    main(args.git_hash, args.git_date)
