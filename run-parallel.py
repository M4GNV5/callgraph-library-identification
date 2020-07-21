import os, sys, concurrent.futures

with open(sys.argv[1]) as fd:
    libFiles = fd.readlines()

with open(sys.argv[2]) as fd:
    binFiles = fd.readlines()

threadCount = int(sys.argv[3])
combinations = []

for i, libFile in enumerate(libFiles):
    if libFile == "":
        continue

    for j, binFile in enumerate(binFiles):
        if binFile == "":
            continue

        output = "output/combination_{}_{}.txt".format(i, j)
        combinations.append((output, libFile.strip(), binFile.strip()))

def handleCombination(comb):
    output, libFile, binFile = comb

    with open(output, "w+") as fd:
        fd.write("checking if {} contains {}\n\n\n".format(binFile, libFile))
    os.system("python3 bincontainslib.py \"{}\" \"{}\" 2>&1 >> {}".format(binFile, libFile, output))

pool = concurrent.futures.ThreadPoolExecutor(threadCount)
pool.map(handleCombination, combinations)
