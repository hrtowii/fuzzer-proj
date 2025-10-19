# required: setup phase - take arg 1 as a file and check what kind of input it expects, afterwards run mutate backend on it.
# so functions required: setup() -> detect() -> mutate.run(), where .run() will run diff backends etc. flip bits, whatever
def main():
    if len(sys.argv < 2):
        

