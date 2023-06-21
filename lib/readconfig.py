import os
import sys


def read_interfaces(filename):
    f = open(filename, 'r')
    interfaces = []
    for line in f.readlines():
        interface = line.strip('\r\n')
        interfaces.append(interface)
    f.close()
    return interfaces


def main():
    if len(sys.argv) == 2:
        filename = sys.argv[1]
        if not os.path.isfile(filename):
            print(filename + ' does not exist')
            exit(1)
        elif not os.access(filename, os.R_OK):
            print(filename + ' access denied')
            exit(1)
        else:
            read_interfaces(filename)
            exit(1)
    else:
        print('Provide interface config!')


if __name__ == '__main__':
    main()
