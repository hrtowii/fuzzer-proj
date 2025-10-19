# required: setup phase - take arg 1 as a file, take arg 2 as sample, and check what kind of input it expects, afterwards run mutate backend on it.
# so functions required: setup() -> detect() -> mutate.run(), where .run() will run diff backends etc. flip bits, whatever
# midpoint / POC point: take in a binary that accepts csv and json
import argparse

parser = argparse.ArgumentParser(description="simple fuzzer for 6447.")
parser.add_argument()


def main():
    return
