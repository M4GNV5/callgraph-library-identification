import os, sys, r2pipe, concurrent.futures
import networkx as nx, networkx.algorithms as nxa
from scipy.optimize import linear_sum_assignment
import matplotlib.pyplot as plt
from operator import itemgetter

pool = concurrent.futures.ThreadPoolExecutor(16)

def findFunctionFromAddress(functionAddresses, address):
	# assume functionAddresses is sorted
	result = 0
	for curr in functionAddresses:
		if curr > address:
			break
		result = curr

	return result

def extractSymbolAddresses(filename):
	# muh string insertion vulnerability
	cmd = "objdump -d " + filename + " | grep '>:'"
	lines = [line for line in os.popen(cmd).readlines()]

	name2addr = {}
	addr2name = {}
	addresses = [0]
	for line in lines:
		split = line.split(" ")
		address = int(split[0], 16)
		name = split[1][1 : -3]
		name2addr[name] = address
		addr2name[address] = name
		addresses.append(address)

	return name2addr, addr2name, addresses

def createCallGraphFromBinary(filename):
	# these might not be filled, symbols not included will get dummy names later
	name2addr, addr2name, nodes = extractSymbolAddresses(filename)

	# we search for call instructions for actually finding functions
	cmd = "objdump -d '" + filename + "' | grep -E 'call.  [0-9a-f]+' | awk '{print $1 $8;}'"
	lines = [line for line in os.popen(cmd).readlines()]
	for i, line in enumerate(lines):
		split = line.split(":")
		lines[i] = (int(split[0], 16), int(split[1], 16))

	for source, dest in lines:
		if dest not in nodes:
			nodes.append(dest)

		if dest not in addr2name:
			name = "func" + str(dest)
			name2addr[name] = dest
			addr2name[dest] = name
	
	nodes.sort()

	G = nx.DiGraph()
	G.add_nodes_from(nodes)
	for source, dest in lines:
		sourceNode = findFunctionFromAddress(nodes, source)

		if not G.has_edge(sourceNode, dest):
			G.add_edge(sourceNode, dest)

	return G, addr2name

def createCallGraphFromLibrary(filename):
	name2addr, addr2name, addresses = extractSymbolAddresses(filename)
	addresses.sort()

	cmd = "objdump -j .text -r " + filename + " | grep -E 'R_X86_64_PLT32|R_X86_64_PC32' | awk '{print $1\" \"$3;}' | grep -Eo '^[^-]+'"
	lines = [line for line in os.popen(cmd).readlines()]

	G = nx.DiGraph()
	G.add_nodes_from(addresses)
	nextExternal = -1
	for line in lines:
		split = line.split(" ")
		address = int(split[0], 16)
		name = split[1].strip()

		if name not in name2addr:
			G.add_node(nextExternal)
			name2addr[name] = nextExternal
			addr2name[nextExternal] = name
			nextExternal -= 1

		sourceFunc = findFunctionFromAddress(addresses, address)
		targetFunc = name2addr[name]

		if not G.has_edge(sourceFunc, targetFunc):
			G.add_edge(sourceFunc, targetFunc)

	return G, addr2name

def createCallGraphUsingRadare2(filename):
	r = r2pipe.open(filename)
	r.cmd("aaaa")
	functions = r.cmdj("agCj")

	G = nx.DiGraph()
	addr2name = {}
	name2addr = {}
	addr2attrs = {}
	for i, func in enumerate(functions):
		G.add_node(i)

		name = func["name"]
		addr2name[i] = name
		name2addr[name] = i

		r.cmd("s " + name)
		funcInfo = r.cmdj("afij")[0]

		for key in ["regvars", "spvars", "bpvars"]:
			if key not in funcInfo:
				funcInfo[key] = []

		for key in ["nbbs", "edges"]:
			if key not in funcInfo:
				funcInfo[key] = 0

		for key in ["is-pure", "noreturn"]:
			if key not in funcInfo:
				funcInfo[key] = False

		args = [x["type"] for x in funcInfo["regvars"]]
		args += [x["type"] for x in funcInfo["spvars"] if x["kind"] == "arg"]
		args += [x["type"] for x in funcInfo["bpvars"] if x["kind"] == "arg"]

		blocks = r.cmdj("afbj")
		blocks = [x["ninstr"] for x in blocks]
		blocks.sort()

		attributes = {
			"args": args,
			"blocks": blocks,
			"blockCount": funcInfo["nbbs"],
			"edgeCount": funcInfo["edges"],
			"isPure": funcInfo["is-pure"],
			"noReturn": funcInfo["noreturn"],
			# TODO more?
		}
		addr2attrs[i] = attributes

	for i, func in enumerate(functions):
		for name in func["imports"]:
			if name not in name2addr:
				continue
			j = name2addr[name]
			G.add_edge(i, j)

	return G, addr2name, addr2attrs

binFile = sys.argv[1]
libFile = sys.argv[2]
print("generating graphs...")
#binGraph, binLabels = createCallGraphFromBinary(binFile)
#binGraph, binLabels, binFuncAttrs = createCallGraphUsingRadare2(binFile)
#libGraph, libLabels = createCallGraphFromLibrary(libFile)
#libGraph, libLabels, libFuncAttrs = createCallGraphUsingRadare2(libFile)

binData, libData = pool.map(createCallGraphUsingRadare2, [binFile, libFile])
binGraph, binLabels, binFuncAttrs = binData
libGraph, libLabels, libFuncAttrs = libData

binNodes = list(binGraph.nodes())
libNodes = list(libGraph.nodes())

def normalizeLabels(labels):
	for k, v in labels.items():
		if "." in v:
			labels[k] = v[v.rindex(".") + 1 : ]
normalizeLabels(binLabels)
normalizeLabels(libLabels)



def nodeDistance(a, b):
	if binLabels[a] == libLabels[b]:
		return 0
	else:
		return 1
def degreeDistance(a, b):
	inDistance = abs(binGraph.in_degree(a) - libGraph.in_degree(b))
	outDistance = abs(binGraph.out_degree(a) - libGraph.out_degree(b))
	return inDistance + outDistance
def edgeDistance(a, b):
	return nodeDistance(a, b) + degreeDistance(a, b)

def sortedLabelSetDistance(labelsA, labelsB):
	# labelsA == sorted(Ga.neighbors(a))
	# labelsB == sorted(Gb.neighbors(b))
	# this function is called twice, once for successors, once for predecessors
	distance = 0
	iA = 0
	iB = 0
	lenA = len(labelsA)
	lenB = len(labelsB)
	while iA < lenA and iB < lenB:
		if labelsA[iA] < labelsB[iB]:
			distance += 1
			iA += 1
		elif labelsA[iA] > labelsB[iB]:
			distance += 1
			iB += 1
		else:
			iA += 1
			iB += 1

	distance += lenA - iA
	distance += lenB - iB
	return distance
def calculateStarDistanceMatrix():
	binStarLabels = []
	for a in binNodes:
		succLabels = [*map(lambda x: binLabels[x], binGraph.successors(a))]
		precLabels = [*map(lambda x: binLabels[x], binGraph.predecessors(a))]
		succLabels.sort()
		precLabels.sort()
		binStarLabels.append((a, succLabels, precLabels))

	distanceMatrix = []

	for b in libNodes:
		bSuccLabels = [*map(lambda x: libLabels[x], libGraph.successors(b))]
		bPrecLabels = [*map(lambda x: libLabels[x], libGraph.predecessors(b))]
		bSuccLabels.sort()
		bPrecLabels.sort()

		row = []
		for a, aSuccLabels, aPrecLabels in binStarLabels:
			distance = edgeDistance(a, b)
			distance += sortedLabelSetDistance(aSuccLabels, bSuccLabels)
			distance += sortedLabelSetDistance(aPrecLabels, bPrecLabels)
			row.append(distance)
		distanceMatrix.append(row)

	return distanceMatrix



def attributeDistance(a, b):
	dist = 0
	attrsA = binFuncAttrs[a]
	attrsB = libFuncAttrs[b]

	argsA = attrsA["args"]
	argsB = attrsB["args"]
	dist += abs(len(argsA) - len(argsB))
	for i in range(min(len(argsA), len(argsB))):
		if argsA[i] != argsB[i]:
			dist += 1

	#if attrsA["isPure"] != attrsB["isPure"]:
	#	dist += 10
	#if attrsA["noReturn"] != attrsB["noReturn"]:
	#	dist += 10

	dist += abs(attrsA["blockCount"] - attrsB["blockCount"])
	dist += abs(attrsA["edgeCount"] - attrsB["edgeCount"])

	dist += sortedLabelSetDistance(attrsA["blocks"], attrsB["blocks"])

	#dist += abs(attrsA["numLocals"] - attrsB["numLocals"])
	#dist += abs(attrsA["stackSize"] - attrsB["stackSize"]) // 8

	return dist

def maxPossibleAttributeDistance(a, b):
	dist = 0
	attrsA = binFuncAttrs[a]
	attrsB = libFuncAttrs[b]

	dist += max(len(attrsA["args"]), len(attrsB["args"]))

	#dist += 10 #isPure
	#dist += 10 #noReturn

	dist += max(attrsA["blockCount"], attrsB["blockCount"])
	dist += max(attrsA["edgeCount"], attrsB["edgeCount"])

	dist += max(len(attrsA["blocks"]), len(attrsB["blocks"]))

	return dist

def attributeEdgeDistance(a, b):
	return attributeDistance(a, b) + degreeDistance(a, b)

def attributeStarDistance(a, b):
	dist = attributeEdgeDistance(a, b)

	aSuccs = binGraph.successors(a)
	aPrecs = binGraph.predecessors(a)
	bSuccs = libGraph.successors(b)
	bPrecs = libGraph.predecessors(b)

	for i in aSuccs:
		dist += min((attributeEdgeDistance(i, j) for j in bSuccs), default=0)

	for i in aPrecs:
		dist += min((attributeEdgeDistance(i, j) for j in bPrecs), default=0)

	return dist

def maxPossibleAttributeEdgeDistance(a, b):
	dist = maxPossibleAttributeDistance(a, b)
	dist += max(binGraph.in_degree(a), libGraph.in_degree(b))
	dist += max(binGraph.out_degree(a), libGraph.out_degree(b))

	return dist

def maxPossibleAttributeStarDistance(a, b):
	dist = maxPossibleAttributeEdgeDistance(a, b)

	aSuccs = binGraph.successors(a)
	aPrecs = binGraph.predecessors(a)
	bSuccs = libGraph.successors(b)
	bPrecs = libGraph.predecessors(b)

	for i in aSuccs:
		dist += max((maxPossibleAttributeEdgeDistance(i, j) for j in bSuccs), default=0)

	for i in aPrecs:
		dist += max((maxPossibleAttributeEdgeDistance(i, j) for j in bPrecs), default=0)

	return dist

def calculateAttributeStarDistanceMatrix():
	def createRow(b):
		row = []
		for a in binNodes:
			row.append(attributeStarDistance(a, b))

		return row

	result = pool.map(createRow, libNodes)
	return list(result)



def printDistanceMatrix(distanceMatrix):
	for i, a in enumerate(binNodes):
		print(29 * " " + i * "   ┃" + "   ┏> " + binLabels[a])

	for y, row in enumerate(distanceMatrix):
		print("{:30}".format(libLabels[libNodes[y]]), end="")
		for x, distance in enumerate(row):
			print("{:3}".format(distance), end=" ")
		print()

def dumpDistanceMatrix(distanceMatrix):
	with open("distancematrix.csv", "w+") as fd:
		fd.write(",")
		for a in binNodes:
			fd.write(binLabels[a] + ",")
		fd.write("\n")

		for y, row in enumerate(distanceMatrix):
			fd.write(libLabels[libNodes[y]] + ",")
			for x, distance in enumerate(row):
				fd.write(str(distance) + ",")
			fd.write("\n")

print("generating {}x{} distance matrix...".format(len(binNodes), len(libNodes)))
#distanceMatrix = calculateStarDistanceMatrix()
distanceMatrix = calculateAttributeStarDistanceMatrix()
#printDistanceMatrix(distanceMatrix)
dumpDistanceMatrix(distanceMatrix)

print("approximating assignment problem...")
aIndices, bIndices = linear_sum_assignment(distanceMatrix)

print("DONE")

totalDistance = 0
maxPossibleDistance = 0
correctMatches = 0
wrongMatches = 0
missingMatches = 0
for b, a in zip(aIndices, bIndices):
	distance = distanceMatrix[b][a]
	totalDistance += distance
	maxPossibleDistance += maxPossibleAttributeStarDistance(a, b)

	aLabel = binLabels[binNodes[a]]
	bLabel = libLabels[libNodes[b]]

	correctMatchDistance = None
	for i, x in enumerate(distanceMatrix[b]):
		if binLabels[binNodes[i]] == bLabel:
			correctMatchDistance = x

	#print("Match {:30} to {:30} with distance {}. Distance to correct match {}"
	#	.format(aLabel, bLabel, distance, correctMatchDistance))

	if aLabel == bLabel:
		correctMatches += 1
	elif correctMatchDistance is None:
		missingMatches += 1
	else:
		wrongMatches += 1

if maxPossibleDistance == 0:
	normalizedDistance = 1
else:
	normalizedDistance = totalDistance / maxPossibleDistance

if correctMatches == 0 and wrongMatches == 0:
	matchRate = 0
else:
	matchRate = correctMatches / (correctMatches + wrongMatches)

print("Normalized edit distance : {}".format(normalizedDistance))
print("Correct match rate: {}".format(matchRate))
print("Approximated edit distance: {}".format(totalDistance))
print("Max possible edit distance: {}".format(maxPossibleDistance))
print("Correct matches: {}\nWrong matches: {}\nMissing functions: {}".format(correctMatches, wrongMatches, missingMatches))

'''
matcher = nxa.isomorphism.DiGraphMatcher(binGraph, libGraph)
if matcher.subgraph_is_isomorphic():
	print("HEUREKA!")
else:
	print("no dice")

distance = nxa.similarity.graph_edit_distance(binGraph, libGraph)
print(distance, len(binGraph.nodes()), len(libGraph.nodes()))

nx.draw(binGraph, labels=binLabels)
plt.show()

nx.draw(libGraph, labels=libLabels)
plt.show()

#nx.set_node_attributes(binGraph, binLabels, 'label')
#nx.write_graphml(binGraph, 'bin.graphml')

#nx.set_node_attributes(libGraph, libLabels, 'label')
#nx.write_graphml(binGraph, 'lib.graphml')
'''