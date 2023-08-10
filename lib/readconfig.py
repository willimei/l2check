import os
import yaml


def read_yaml_file(filename) -> dict:
    if not os.path.isfile(filename):
        print(filename + ' does not exist')
        exit(1)
    elif not os.access(filename, os.R_OK):
        print(filename + ' access denied')
        exit(1)
    else:
        with open(filename, 'r') as file:
            try:
                config = yaml.safe_load(file)
            except yaml.YAMLError as err:
                print(err)

    return config

