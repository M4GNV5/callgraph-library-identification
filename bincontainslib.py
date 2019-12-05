import os, sys, networkx as nx, matplotlib.pyplot as plt

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

	cmd = "objdump -j .text -r " + filename + " | grep 'R_X86_64_PLT32' | awk '{print $1\" \"$3;}' | grep -Eo '^[^-]+'"
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


	
binFile = sys.argv[1]
libFile = sys.argv[2]
binGraph, binLabels = createCallGraphFromBinary(binFile)
libGraph, libLabels = createCallGraphFromLibrary(libFile)

matcher = nx.algorithms.isomorphism.DiGraphMatcher(binGraph, libGraph)
if matcher.subgraph_is_isomorphic():
	print("HEUREKA!")
else:
	print("no dice")

nx.draw(binGraph, labels=binLabels)
plt.show()

#nx.set_node_attributes(binGraph, binLabels, 'label')
#nx.write_graphml(binGraph, 'bin.graphml')

#nx.set_node_attributes(libGraph, libLabels, 'label')
#nx.write_graphml(binGraph, 'lib.graphml')