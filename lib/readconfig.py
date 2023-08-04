import os
import sys


def read_file_lines(filename):
    f = open(filename, 'r')
    lines = []
    for line in f.readlines():
        line = line.strip('\r\n')
        lines.append(line)
    f.close()
    return lines


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
            read_file_lines(filename)
            exit(1)
    else:
        print('Provide interface config!')


if __name__ == '__main__':
    main()
