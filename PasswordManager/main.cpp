#include <iostream>
#include <fstream>
#include <string>
#include <bitset>
#include <vector>


const char KEY = 0xCCDC;
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

void EncryptPassword(const std::string& password, const char key)
{
	char encryted_char;
	
	for (const char bin : password)
	{
		 encryted_char ^= key;
	}
}
void DisplayMenu()
{
	std::cout << "1.Add Password\n2.Retrieve Saved Passwords\n3.Delete Password\nExit\n";

}

void AddNewPassword()
{
	std::string user, app_name,password;
	std::cout << "Enter UserName: ";
	std::getline(std::cin, user);

	std::cout << "Enter Application Name: ";
	std::getline(std::cin, app_name);

	std::cout << "Enter New Password: ";
	std::getline(std::cin, password);


}

int main()
{


	std::cin.get();
}