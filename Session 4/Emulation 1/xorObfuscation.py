import sys

def help():
	print("Example: xorObfuscation.py --key 0x56 --filename shellcode.txt")

def main():
	argv = sys.argv
	argc = len(argv) - 1
	if (argc < 4):
		help()
		return 0

	if (argv[1] != "--key"):
		help()
		return 0

	if (argv[3] != "--filename"):
		help()
		return 0

	key = int(argv[2], 16)
	filename = argv[4]
	fileShellcode = open(filename, "r")

	shellcode = fileShellcode.read().split(", ")
	print()
	print(", ".join(["0x{:02x}".format(int(x, 16) ^ key) for x in shellcode]))


if __name__ == "__main__":
	main()