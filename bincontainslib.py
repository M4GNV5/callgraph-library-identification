import os, sys, r2pipe
import networkx as nx, networkx.algorithms as nxa
from scipy.optimize import linear_sum_assignment
import matplotlib.pyplot as plt
from operator import itemgetter

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
	r.cmd("aaa")
	functions = r.cmdj("agCj")

	G = nx.DiGraph()
	addr2name = {}
	name2addr = {}
	for i, func in enumerate(functions):
		G.add_node(i)

		name = func["name"]
		addr2name[i] = name
		name2addr[name] = i

	for i, func in enumerate(functions):
		for name in func["imports"]:
			j = name2addr[name]
			G.add_edge(i, j)

	return G, addr2name

binFile = sys.argv[1]
libFile = sys.argv[2]
print("generating graphs...")
#binGraph, binLabels = createCallGraphFromBinary(binFile)
binGraph, binLabels = createCallGraphUsingRadare2(binFile)
libGraph, libLabels = createCallGraphFromLibrary(libFile)
#libGraph, libLabels = createCallGraphUsingRadare2(libFile)

binNodes = list(binGraph.nodes())
libNodes = list(libGraph.nodes())

for k, v in binLabels.items():
	if v.startswith("sym."):
		binLabels[k] = v[4:]



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

def printDistanceMatrix(distanceMatrix):
	for i, a in enumerate(binNodes):
		print(29 * " " + i * "   ┃" + "   ┏> " + binLabels[a])

	for y, row in enumerate(distanceMatrix):
		print("{:30}".format(libLabels[libNodes[y]]), end="")
		for x, distance in enumerate(row):
			print("{:3}".format(distance), end=" ")
		print()


print("generating {}x{} distance matrix...".format(len(binNodes), len(libNodes)))
distanceMatrix = calculateStarDistanceMatrix()
#printDistanceMatrix(distanceMatrix)

print("approximating assignment problem...")
aIndices, bIndices = linear_sum_assignment(distanceMatrix)

print("DONE")

totalDistance = 0
for b, a in zip(aIndices, bIndices):
	totalDistance += distanceMatrix[b][a]

	a = list(binGraph.nodes())[a]
	b = list(libGraph.nodes())[b]
	print("Match {:30} to {:30}".format(binLabels[a], libLabels[b]))

print("Approximated edit distance: {}".format(totalDistance))

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