#!/usr/bin/env python

import argparse


def main():
    parser = argparse.ArgumentParser(description="Check Ganglia Argument Parser")
    parser.add_argument('-i', '--hostname',type=str, help='The host where the Ganglia service is running', required=True)
    parser.add_argument('-p', '--port', type=int,help='The Ganglia service port to connect', required=True)
    parser.add_argument('-x', '--xmlparameters', help='The XML Parameters',required=True, nargs='*')
    args = parser.parse_args()

    print args.hostname
    print args.port
    print args.xmlparameters


if __name__ == '__main__':
    main()
