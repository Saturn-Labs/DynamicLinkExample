#include <windows.h>
#include <iostream>

#pragma optimize("", off)
class __declspec(noinline) Tests {
public:
	Tests() {
		std::cout << "Tests constructor" << std::endl;
	};

	~Tests() {
		std::cout << "Tests destructor" << std::endl;
	};

	int DoAddition(int a, int b) {
		return a + b;
	}
};
#pragma optimize("", on)

int main(int argc, char* argv[]) {
	{
		Tests().DoAddition(1, 1);
		std::cout << "Outscope" << std::endl;
	}

	LoadLibrary("./Library.dll");
	std::cout << std::hex << GetLastError() << std::endl;
	std::cin.get();
	return 0;
}