#include <iostream>
#include <fstream>
#include <string>
#include <bitset>
#include <vector>


const char KEY = 0xAA;
std::string GetMasterPassword()
{
	/*
		Takes master password and return it if the characters are more than four
	
	*/
	std::string master_password,pwd;
	std::cout << "Enter Master Password: ";
	std::getline(std::cin, master_password);

	if (master_password.size() < 4)
	{
		std::cout << "Master password should be more than 4 characters" << std::endl;
		return GetMasterPassword();
	}
	return master_password;
}

std::vector<std::bitset<8>> ConvertToBinary(const std::string& ascii)
{	
	/*
		it accept a string of ascii values,convert it into a binary format
		in 8bits then append it into the end of a vector container
		then return the entire container
	*/
	std::vector<std::bitset<8>> binary;
	for (const char ch : ascii)
	{
		binary.emplace_back(std::bitset<8>(ch));
	}
	return binary;
}

std::string GetPasswordInBinary(const std::string& password)
{

	/*
		takes in a string argument of password then convert each character into it's 
		ascii value then combines the values into a string and returns it

	*/
	std::string binary;
	std::vector<std::bitset<8>> text;
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
	/*
	
	
	
	*/
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
	std::cout << "1.Add Password\n2.Retrieve Saved Passwords\n3.Delete Password\n4.Exit\n";
	std::cin >> choice;

	return choice;
}

void AddNewPassword(const std::string& filepath)
{
	/*
		Allows you to add password to encrypted password 
		to a file with a username and unique application name
	
	*/
	std::string user, app_name, password;
	std::cout << "Enter UserName: ";
	std::cin.ignore();
	std::getline(std::cin, user);

	std::cout << "Enter Application Name: ";
	std::getline(std::cin, app_name);

	std::cout << "Enter New Password: ";
	std::getline(std::cin, password);

	std::fstream out(filepath);
	std::string line;

	while (std::getline(out, line))
	{
		if (line.find("APP NAME: " + app_name) != std::string::npos)
			return AddNewPassword(filepath);
	}

	password = GetPasswordInBinary(password);
	password = EncryptPassword(password, KEY);

	std::ofstream file(filepath, std::ios::app);
	if (file.is_open())
	{
		file << "APP NAME: " << app_name << std::endl;
		file << "USERNAME: " << user << std::endl;
		file << "PASSWORD: " << password << std::endl;
		std::cout << "Password added successfully" << std::endl;

	}
	file.close();

}

void DeletePassword(const std::string& filepath)
{
	/*
		Open passwords file check if there exists a password with a specific username
		and application name if so then it rewrites the entire into temporary file
		without that user credentials 
		then removes the old file and rename to new file with old file's name
	
	*/
	std::ifstream file(filepath);
	std::ofstream out("temp.txt");

	bool skipNextLine = false;
	std::string line, app, user;

	std::cout << "Enter UserName: ";
	std::cin.ignore();
	std::getline(std::cin, user);

	std::cout << "Enter App Name: ";
	std::getline(std::cin, app);

	if (file.is_open())
	{
		while (std::getline(file, line))
		{
			if (line.find("APP NAME: " + app) != std::string::npos)
			{
				skipNextLine = true;
			}
			else if (line.find("USERNAME: " + user) != std::string::npos)
			{
				skipNextLine = true;
			}
			else if (skipNextLine && line.find("PASSWORD: ") != std::string::npos)
			{
				skipNextLine = false;
			}
			else
				out << line << std::endl;
		}
	}
	file.close();
	out.close();
	std::remove(filepath.c_str());
	std::rename("temp.txt", filepath.c_str());
}

std::string DecryptPassword(const std::string& pwd, const char key)
{
	/*
		Decrypt the encrypted using XOR decryption to its original
		text then returns the decrypted text
	
	*/
	std::vector<std::bitset<8>>binary;
	std::string bit;
	std::string decrypt;
	for (char ch : pwd)
	{

		bit += ch ^ key;
		if (bit.size() == 8)
		{
			binary.emplace_back(bit);
			bit = "";
		}
	}
		
	for (const auto& ch : binary)
	{
		decrypt += static_cast<char>(ch.to_ulong());
	}
	return decrypt;
}
std::string RetrievePassword(const std::string& filepath)
{
	/*
		Check if password registered with a certain application name exists
		and check if the provided master password matches the master password saved in the file
		if so it returns the decrypted form of the stored password
	
	*/
	std::ifstream file(filepath);
	std::ifstream out(filepath);
	if (!file)
	{
		std::cerr << "Unable to open file" << std::endl;
		return "";
	}

	std::string user, password, master_pwd;
	std::string line,text;
	std::cout << "Enter App Name: ";
	std::cin.ignore();
	std::getline(std::cin, user);

	std::cout << "Enter Master Password: ";
	std::getline(std::cin, master_pwd);
	
	master_pwd = GetPasswordInBinary(master_pwd);
	master_pwd = EncryptPassword(master_pwd, KEY);
	
	while (std::getline(file, line))
	{
		if (line.find("MASTER: " + master_pwd) != std::string::npos)
		{
			//Master password provided is correct
		}

	}
	
	while (std::getline(out, text))
	{
		if (text.find("APP NAME: " + user) != std::string::npos)
		{
			std::getline(out, text);
			std::getline(out, text);

			if (text.find("PASSWORD: ") != std::string::npos)
				return text.substr(text.find("PASSWORD: ") + 10);
		}
	}
	std::cout << "Error: Invalid Credentials" << std::endl;

	
	file.close();
	return "";
}
void CheckMasterPassword(const std::string filepath, const char key)
{
	/*
		Checks if master password has already been registered if not
		get master password encrypt it and save into a file
	*/
	std::string master_pwd,pwd,line;
	
	std::ifstream file(filepath);
	std::ofstream out(filepath, std::ios::app);

	master_pwd = GetMasterPassword();
	pwd = GetPasswordInBinary(master_pwd);
	pwd = EncryptPassword(pwd, KEY);

	while (std::getline(file, line))
	{
		if (line.find("MASTER: ") != std::string::npos)
		{
			std::cout << "Master credentials already exists" << std::endl;
			return;
		}
	}
	out << "MASTER: " << pwd << std::endl;
	std::cout << "Saved Successfully" << std::endl;
	file.close();
	out.close();
	
}
int main()
{
	int choice;
	std::string m_pwd;

	std::string filepath = "encryptedpasswords.txt";
	//CheckMasterPassword(filepath, KEY);
	do {
		choice = DisplayMenu();

		switch (choice)
		{
		case 1:
			AddNewPassword(filepath);
			break;
		case 2:
			m_pwd = RetrievePassword(filepath);
			if (!m_pwd.empty())
			{
				std::cout << "Password: " << DecryptPassword(m_pwd, KEY) << std::endl;
			}
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
	} while (choice != 4);
	std::cin.get();
}
