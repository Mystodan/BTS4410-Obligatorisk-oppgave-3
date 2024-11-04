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
    """Return a list of folder names in the test directory."""
    assert isGen, "Test data not generated."
    return os.listdir(TEST_DIRECTORY)

def getTestData(*args):
    """Extract the test data from the zip files."""
    global isGen 
    # Check if the test data is already extracted.
    if os.path.exists(TEST_DIRECTORY):
        print("Test files already extracted.")
        isGen = True # Set the flag to True.
        return # early return
    # Extract the test data.
    os.mkdir(TEST_DIRECTORY) # Create the test directory.
    for arg in args:
        with zipfile.ZipFile(arg,"r") as z:
            z.extractall(TEST_DIRECTORY+arg.split(".")[0]) # Extract the files.
    print(f"{len(args)} Test files extracted in {TEST_DIRECTORY}*")
    isGen = True # Set the flag to True.

