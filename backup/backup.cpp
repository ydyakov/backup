#include <iostream>
#include <unordered_map>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>

namespace fs = std::filesystem;

enum PathTypeState
{
	Directory,
	File,
	Error
};

enum Command
{
	CREATE,
	UPDATE,
	CHECK,
	EXTRACT,
	ERROR
};

struct HashData
{
	std::string hash;
	size_t size;
	std::vector<char> data;
};

struct UniqueFileRecord
{
	std::string hash;
	std::string path;
	std::time_t lastModified;
};

struct CommandParameter
{
	Command action;
	std::string archive;
	std::vector<std::string> dirPaths;
	bool hashOnlyFlag = false;
};


struct Helpper
{
	static CommandParameter computeAcction(int argc, char* argv[]) {
		CommandParameter result;
		if (argc < 3)
		{
			std::cerr << "Use: backup.exe create|extract|check|update  hash-only? <name> <directory>+" << std::endl;
			result.action = Command::ERROR;
			return result;
		}

		std::string command = argv[1];
		std::transform(command.begin(), command.end(), command.begin(), [](unsigned char c)
		{
			return std::tolower(c);
		});

		if (command != "create" && command != "update" && command != "check" && command != "extract") 
		{
			std::cerr << "Use: backup.exe create|extract|check|update hash-only? <name> <directory>+" << std::endl;
			result.action = Command::ERROR;
			return result;
		}

		if (command == "update")
		{
			result.action = Command::UPDATE;
		}
		else if (command == "create")
		{
			result.action = Command::CREATE;
		}
		else if (command == "check")
		{
			result.action = Command::CHECK;
		}
		else if (command == "extract")
		{
			result.action = Command::EXTRACT;
		}

		int index = 2;
		if (std::string(argv[2]) == "hash-only")
		{
			result.hashOnlyFlag = true;
			index++;
		}

		if (index >= argc)
		{
			std::cerr << "Error: Missing <name> parameter." << std::endl;
			result.action = Command::ERROR;
			return result;
		}
		result.archive = argv[index++];

		if (index >= argc)
		{
			std::cerr << "Error: Missing <directory> parameters." << std::endl;
			result.action = Command::ERROR;
			return result;
		}

		for (int i = index; i < argc; ++i)
		{
			result.dirPaths.push_back(argv[i]);
		}

		return result;
	}

	static PathTypeState ensureDirectoryExists(const fs::path& inputPath) {
		if (!fs::exists(inputPath))
		{
			fs::path dirPath = inputPath;

			if (fs::is_regular_file(inputPath) || inputPath.has_extension())
			{
				dirPath = inputPath.parent_path();
			}
			try
			{
				if (!fs::exists(dirPath))
				{
					if (fs::create_directories(dirPath))
					{
						std::cout << "Created directories for path: " << dirPath << std::endl;
					}
					else
					{
						std::cerr << "Failed to create directories for path: " << dirPath << std::endl;
						return PathTypeState::Error;
					}
				}
			}
			catch (const fs::filesystem_error& e)
			{
				std::cerr << "Error: " << e.what() << std::endl;
				return PathTypeState::Error;;
			}
		}

		if (fs::is_directory(inputPath))
		{
			return PathTypeState::Directory;
		}

		return PathTypeState::File;
	}

	// Сериализация на UniqueFileRecord
	static void serializeFileRecord(const UniqueFileRecord& record, std::ofstream& outStream) 
	{

		size_t pathLength = record.path.size();
		// сериализация на path
		outStream.write(reinterpret_cast<const char*>(&pathLength), sizeof(pathLength));
		outStream.write(record.path.data(), pathLength);

		// Сериализация на `lastModified`
		outStream.write(reinterpret_cast<const char*>(&record.lastModified), sizeof(record.lastModified));

		// Сериализация на hash
		size_t hashLength = record.hash.size();
		outStream.write(reinterpret_cast<const char*>(&hashLength), sizeof(hashLength));
		outStream.write(record.hash.data(), hashLength);
	}

	// Сериализация на HashData
	static void serializeHashData(const HashData& record, std::ofstream& outStream) 
	{

		// Сериализация на hash
		size_t hashLength = record.hash.size();
		outStream.write(reinterpret_cast<const char*>(&hashLength), sizeof(hashLength));
		outStream.write(record.hash.data(), hashLength);

		// Сериализация на size
		outStream.write(reinterpret_cast<const char*>(&record.size), sizeof(record.size));

		// Сериализация на data
		size_t dataLength = record.data.size();
		outStream.write(reinterpret_cast<const char*>(&dataLength), sizeof(dataLength));
		outStream.write(record.data.data(), dataLength);

	}


	// Десериализация на FileRecord
	static UniqueFileRecord deserializeFileRecord(std::ifstream& inStream) 
	{
		UniqueFileRecord record;

		// Десериализация на path
		size_t pathLength;
		inStream.read(reinterpret_cast<char*>(&pathLength), sizeof(pathLength));
		std::string path(pathLength, '\0');
		inStream.read(path.data(), pathLength);
		record.path = path;

		// Десериализация на lastModified
		std::time_t lastModified;
		inStream.read(reinterpret_cast<char*>(&lastModified), sizeof(lastModified));
		record.lastModified = lastModified;

		// Десериализация на hash
		size_t hashLength;
		inStream.read(reinterpret_cast<char*>(&hashLength), sizeof(hashLength));
		record.hash.resize(hashLength);
		inStream.read(record.hash.data(), hashLength);

		return record;
	}

	// Десериализация на HashData
	static HashData deserializeHashData(std::ifstream& inStream)
	{
		HashData record;

		// Десериализация на hash
		size_t hashLength;
		inStream.read(reinterpret_cast<char*>(&hashLength), sizeof(hashLength));
		record.hash.resize(hashLength);
		inStream.read(record.hash.data(), hashLength);

		// Десериализация на size
		inStream.read(reinterpret_cast<char*>(&record.size), sizeof(record.size));

		// Десериализация на data
		size_t dataLength;
		inStream.read(reinterpret_cast<char*>(&dataLength), sizeof(dataLength));
		record.data.resize(dataLength);
		inStream.read(record.data.data(), dataLength);

		return record;
	}

	static void compareFileTables(std::unordered_map<std::string, UniqueFileRecord> archive, std::unordered_map<std::string, UniqueFileRecord> fileSysytem)
	{
		std::cout << " -------------- Files only in archive: -----------------------" << std::endl;
		for (auto [path, fileRecord] : archive)
		{
			if (fileSysytem.find(path) == fileSysytem.end())
			{
				std::cout << path << std::endl;
			}
		}

		std::cout << " -------------- Files only in file sysytem: -----------------------" << std::endl;
		for (auto [path, fileRecord] : fileSysytem)
		{
			if (archive.find(path) == archive.end())
			{
				std::cout << path << std::endl;
			}
		}

		std::cout << " ----------------    common files:    --------------------------" << std::endl;
		for (auto [path, fileRecord] : fileSysytem)
		{

			if (archive.find(path) != archive.end())
			{
				bool isEqual = archive[path].hash == fileSysytem[path].hash;
				std::cout << path << (isEqual ? " - Identical  " : " - Diferent") << std::endl;
			}
		}

	}

	static std::string hashBinaryContent(const std::vector<char>& data) {
		const uint64_t FNV_prime = 1099511628211u;
		const uint64_t FNV_offset_basis = 14695981039346656037u;

		uint64_t hash = FNV_offset_basis;

		for (char byte : data) {
			hash ^= static_cast<uint64_t>(static_cast<unsigned char>(byte));
			hash *= FNV_prime;
		}

		std::ostringstream oss;
		oss << std::hex << std::setfill('0') << std::setw(16) << hash;
		return oss.str();
	}
};

class Repository
{
private:
	std::unordered_map<std::string, UniqueFileRecord> fileTable;

	std::unordered_map<std::string, HashData> hashData;

	void importFileFromFileSystem(const fs::path& filePath)
	{
		std::ifstream inputFile(filePath, std::ios::binary);
		if (!inputFile)
		{
			std::cerr << "Error on open file: " << filePath << std::endl;
			return;
		}

		inputFile.seekg(0, std::ios::end);
		std::streamsize fileSize = inputFile.tellg();
		inputFile.seekg(0, std::ios::beg);

		std::vector<char> buffer(fileSize);

		if (!inputFile.read(buffer.data(), fileSize))
		{
			std::cerr << "Error on read form file. " << std::endl;
			return;
		}

		inputFile.close();

		std::string fileHash = Helpper::hashBinaryContent(buffer);

		if (fileTable.find(filePath.string()) == fileTable.end())
		{
			fileTable[filePath.string()] = UniqueFileRecord
			{
				fileHash,
				filePath.string(),
				std::filesystem::last_write_time(filePath).time_since_epoch().count()
			};
			std::cout << "Added file to archive: Hash: " << fileHash << " File: " << filePath << std::endl;
		}
		else if (fileHash != fileTable[filePath.string()].hash)
		{
			fileTable[filePath.string()].hash = fileHash;
			std::cout << "Update file to archive: new Hash: " << fileHash << " File: " << filePath << std::endl;
		}

		hashData[fileHash] = HashData
		{
			fileHash,
			buffer.size(),
			buffer
		};
	}

public:

	std::unordered_map<std::string, UniqueFileRecord> GetFileTable()
	{
		return fileTable;
	}

	void importAllFromFileSystem(const fs::path& path)
	{
		std::vector<fs::path> files;

		try
		{
			if (!fs::exists(path) || !fs::is_directory(path))
			{
				std::cerr << "Path is not valid directory: " << path << std::endl;
				return;
			}

			for (const fs::directory_entry entry : fs::recursive_directory_iterator(path))
			{
				if (fs::is_regular_file(entry.path())) {
					files.push_back(entry.path());
				}
			}
		}
		catch (const std::exception& e) {
			std::cerr << "Error with directory: " << e.what() << std::endl;
		}

		for (const fs::path filePath : files)
		{
			importFileFromFileSystem(filePath);
		}
	}

	void restoreFileToFileSystem(std::string dirPathString)
	{
		fs::path dirPath = dirPathString;

		if (Helpper::ensureDirectoryExists(dirPath) != PathTypeState::Directory)
		{
			std::cerr << "Path is not valid directory: " << dirPath << std::endl;
			return;
		}

		for (auto [path, fileRecord] : fileTable)
		{

			fs::path fullPath = dirPath / fileRecord.path;
			if (!Helpper::ensureDirectoryExists(fullPath))
			{
				continue;
			}
			std::ofstream outStream(fullPath, std::ios::binary);
			if (!outStream.is_open()) {
				std::cerr << "Error in open file : " << fullPath << std::endl;
				continue;
			}

			HashData hashDataRecord = hashData[fileRecord.hash];

			outStream.write(hashDataRecord.data.data(), hashDataRecord.data.size());
			outStream.close();
			std::cout << "Restore to file sysytem: " << fullPath << std::endl;

		}
	}

	void serializeToArchive(const std::string& fileName) {
		std::ofstream outStream(fileName, std::ios::binary);
		if (!outStream.is_open()) {
			std::cerr << "Error on store to archive." << std::endl;
			return;
		}

		// save the size of file table
		size_t filesCount = static_cast<size_t>(fileTable.size());
		outStream.write(reinterpret_cast<const char*>(&filesCount), sizeof(filesCount));

		for (const auto& [hash, fileRecord] : fileTable)
		{
			Helpper::serializeFileRecord(fileRecord, outStream);
		}

		// save the size of hash data
		size_t hashCount = static_cast<size_t>(hashData.size());
		outStream.write(reinterpret_cast<const char*>(&hashCount), sizeof(hashCount));

		for (const auto& [hash, hashRecord] : hashData)
		{
			Helpper::serializeHashData(hashRecord, outStream);
		}

		outStream.close();
	}

	void deserializeFromArchive(const std::string& fileName)
	{
		fileTable.clear();
		hashData.clear();

		std::ifstream inStream(fileName, std::ios::binary);
		if (!inStream.is_open()) {
			std::cerr << "Error on open archive. " << std::endl;
			return;
		}

		// read the size of file table
		size_t filesCount;
		inStream.read(reinterpret_cast<char*>(&filesCount), sizeof(filesCount));

		for (int i = 0; i < filesCount; i++)
		{
			UniqueFileRecord fileRecord = Helpper::deserializeFileRecord(inStream);
			fileTable[fileRecord.path] = fileRecord;
		}

		// read the size of hash data
		size_t hashDataCount;
		inStream.read(reinterpret_cast<char*>(&hashDataCount), sizeof(hashDataCount));

		for (int i = 0; i < hashDataCount; i++)
		{
			HashData hashRecord = Helpper::deserializeHashData(inStream);
			hashData[hashRecord.hash] = hashRecord;
		}

		inStream.close();

	}
};

int main(int argc, char* argv[]) {

	CommandParameter command = Helpper::computeAcction(argc, argv);

	if (command.action == Command::ERROR)
	{
		return 1;
	}

	if (command.action == Command::UPDATE)
	{
		Repository repo;
		repo.deserializeFromArchive(command.archive);
		for (std::string dirPath : command.dirPaths)
		{
			repo.importAllFromFileSystem(dirPath);
		}
		repo.serializeToArchive(command.archive);
	}
	else if (command.action == Command::CREATE)
	{
		Repository repo;
		for (std::string dirPath : command.dirPaths)
		{
			repo.importAllFromFileSystem(dirPath);
		}
		repo.serializeToArchive(command.archive);
	}
	else if (command.action == Command::CHECK)
	{
		Repository archive;
		Repository fileSystem;
		archive.deserializeFromArchive(command.archive);
		for (std::string dirPath : command.dirPaths)
		{
			fileSystem.importAllFromFileSystem(dirPath);
		}
		std::system("cls");
		Helpper::compareFileTables(archive.GetFileTable(), fileSystem.GetFileTable());

	}
	else if (command.action == Command::EXTRACT)
	{
		Repository repo;
		repo.deserializeFromArchive(command.archive);
		repo.restoreFileToFileSystem(command.dirPaths[0]);

	}

	return 0;
}
