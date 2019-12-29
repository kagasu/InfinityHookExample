#include <Windows.h>
#include <iostream>

int main()
{
	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, 3900);
	std::cout << std::hex << hProcess << std::endl;

	system("pause");
	return 0;
}