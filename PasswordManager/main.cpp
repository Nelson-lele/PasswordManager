#include <iostream>
#include <fstream>
#include <string>
#include <bitset>
#include <vector>

const char KEY = 0xCCDCDAABBEEFF;
std::string GetMasterPassword()
{
	std::string master_password;
	std::cout << "Enter Master Password: ";
	std::getline(std::cin, master_password);

	if (master_password.size() < 4)
		return GetMasterPassword();
	return master_password;
}

std::vector<std::bitset<16>> ConvertToBinary(const std::string& ascii)
{	
	std::vector<std::bitset<16>> binary;
	for (const char ch : ascii)
	{
		binary.emplace_back(std::bitset<16>(ch));
	}
	return binary;
}

std::string GetPasswordInBinary(const std::string& password)
{
	std::string binary;
	std::vector<std::bitset<16>> text;
	std::string binaryText;
	for (const char bin : password)
	{	
		binary = toascii(bin);
		text = ConvertToBinary(binary);
		
		for (const auto& val : text)
			binaryText += val.to_string();
		
	}
	
	return binaryText;
}

std::string EncryptPassword(const std::string& password, const char key)
{
	std::string text;
	for (char bin : password)
	{
		char encryted_char = bin ^ key;
		text += encryted_char;
	}
	return text;
}
int DisplayMenu()
{
	int choice;
	std::cout << "1.Add Password\n2.Retrieve Saved Passwords\n3.Delete Password\nExit\n";
	std::cin >> choice;

	return choice;
}

void AddNewPassword(const std::string& filepath)
{

	std::string user, app_name,password;
	std::cout << "Enter UserName: ";
	std::cin.ignore();
	std::getline(std::cin, user);

	std::cout << "Enter Application Name: ";
	std::getline(std::cin, app_name);

	std::cout << "Enter New Password: ";
	std::getline(std::cin, password);
	
	password = GetPasswordInBinary(password);
	password = EncryptPassword(password, KEY);

	std::ofstream file(filepath,std::ios::app);
	if (file.is_open())
	{
		file << "______________________________________" << std::endl;
		file << "APP NAME: " << app_name << std::endl;
		file << "USERNAME: " << user << std::endl;
		file << "PASSWORD: " << password << std::endl;
		file << "______________________________________" << std::endl;
	}
	file.close();

}

void DeletePassword(const std::string& filepath)
{
	std::ifstream file(filepath);
	if (file.is_open())
	{
		std::string line, name, app;
		while (std::getline(file, line))
		{
		}
	}
}
std::string RetrievePassword(const std::string& filepath)
{
	std::ifstream file(filepath);
	std::string user,app_name,line,password;
	std::cout << "Enter UserName: ";
	std::getline(std::cin, user);

	std::cout << "Enter Application Name: ";
	std::getline(std::cin, app_name);

	if (file.is_open())
	{
		while (std::getline(file,line))
		{
			if (line.find(user) != std::string::npos && line.find(app_name) != std::string::npos)
			{
				password = line.find(line.substr(line.find("PASSWORD: ") + 1));
			}
		}
	}
	
	file.close();
	return password;
}
int main()
{
	int choice;
	std::string pwd;

	std::string filepath = "encryptedpasswords.txt";
	choice = DisplayMenu();

	switch (choice)
	{
	case 1:
		AddNewPassword(filepath);
		break;
	case 2:
		pwd = RetrievePassword(filepath);
		if (!pwd.empty())
			std::cout << "PASSWORD: " << pwd << std::endl;
		break;
	case 3:
		DeletePassword(filepath);
		break;
	case 4:
		std::exit(0);
		break;
	default:
		std::cout << "Invalid Input" << std::endl;
		break;
	}

	std::cin.get();
}