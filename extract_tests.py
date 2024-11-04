# extract_tests.py 
import os
import zipfile

isGen = False

TEST_SET=(
    "TEST_SET_0.zip",
    "TEST_SET_1.zip",
    "TEST_SET_2.zip",
    )

TEST_DIRECTORY="./tests/"
def getFolderNames() -> list[str]:
    assert isGen, "Test data not generated."
    return os.listdir(TEST_DIRECTORY)

def getTestData(*args):
    global isGen 
    if os.path.exists(TEST_DIRECTORY):
        print("Test files already extracted.")
        isGen = True
        return
    os.mkdir(TEST_DIRECTORY)
    for arg in args:
        with zipfile.ZipFile(arg,"r") as z:
            z.extractall(TEST_DIRECTORY+arg.split(".")[0])
    print(f"{len(args)} Test files extracted in {TEST_DIRECTORY}*")
    isGen = True

