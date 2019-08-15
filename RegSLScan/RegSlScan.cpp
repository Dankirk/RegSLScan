#include <AclAPI.h>
#include <string>
#include <iostream>

#define MAX_KEY_LENGTH 255

bool QueryKey(HKEY hKey, const PTRUSTEEW usersGroup, const std::wstring& path) {

	DWORD cSubKeys = 0;				// number of subkeys 
	DWORD cbMaxSubKey = MAX_KEY_LENGTH;	// longest subkey size 
	DWORD cbSecurityDescriptor;		// size of security descriptor 

	// Get subkey count and security descriptor size
	if (RegQueryInfoKeyW(
		hKey,					// key handle 
		NULL,					// buffer for class name 
		NULL,					// size of class string 
		NULL,					// reserved 
		&cSubKeys,				// number of subkeys 
		&cbMaxSubKey,			// longest subkey size 
		NULL,					// longest class string 
		NULL,					// number of values for this key 
		NULL,					// longest value name 
		NULL,					// longest value data 
		&cbSecurityDescriptor,	// security descriptor size
		NULL)					// last write time 
		!= ERROR_SUCCESS)
		return false;

	// Query security descriptors
	PSECURITY_DESCRIPTOR secDesc = malloc(cbSecurityDescriptor);

	if (RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION, secDesc, &cbSecurityDescriptor) != ERROR_SUCCESS) {
		free(secDesc);
		return false;
	}

	// Parse descriptor and see if users can create symbolic links
	SECURITY_DESCRIPTOR_RELATIVE *sdr = (SECURITY_DESCRIPTOR_RELATIVE *)secDesc;
	ACL *pdacl = (ACL *)((BYTE *)sdr + sdr->Dacl);
	ACCESS_MASK accessMask;

	if (GetEffectiveRightsFromAclW(pdacl, usersGroup, &accessMask) == ERROR_SUCCESS &&
		accessMask & KEY_CREATE_LINK) {

		if ((accessMask & KEY_WRITE) == KEY_WRITE)
			std::wcout << path << L" (writeable)" << std::endl;
		else
			std::wcout << path << L" (link only)" << std::endl;

		free(secDesc);
		return true;
	}

	free(secDesc);

	// Return here if no subkeys are present
	if (cSubKeys == 0)
		return false;

	// Allocate resources and traverse subkeys
	wchar_t* achKey = new wchar_t[cbMaxSubKey + 1];	// buffer for subkey name
	DWORD cbName;								// size of name string 
	DWORD i;
	DWORD success = 0;
	HKEY next;
	std::wstring newpath;

	for (i = 0; i < cSubKeys; i++) {

		cbName = cbMaxSubKey + 1;
		if (RegEnumKeyExW(hKey, i, achKey, &cbName, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
			continue;

		/*
		// "Classes" is pretty big subdirectory, might want to skip it
		if (strcmp(achKey, "Classes") == 0)
			continue;
		*/
		// std::cout << achKey << std::endl; // For debugging

		if (RegOpenKeyExW(hKey, achKey, 0, KEY_READ, &next) != ERROR_SUCCESS)
			continue;
				
		newpath = path + L'\\' + achKey;
		//std::cout << newpath << std::endl; // For debugging
		if (QueryKey(next, usersGroup, newpath)) {

			// We should keep the list shorter by breaking after discovering 5 consecutive subkeys users may create symbolic links in.
			success++;
			if (success >= 5 && success > i) {
				RegCloseKey(next);
				std::wcout << L"Assuming all subkeys in: " << path << L" are accessible this way..." << std::endl;
				break;
			}
		}

		RegCloseKey(next);
	}
	delete[] achKey;
	return false;
}

int __cdecl wmain(int argc, wchar_t* argv[]) {

	// Get users group sid
	SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
	PSID pUsersSid;

	if (!AllocateAndInitializeSid(&sia, 2,
		SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS,
		0, 0, 0, 0, 0, 0, &pUsersSid))

		return 0;

	// Build deescriptor we can use to determine user groups access
	TRUSTEEW usersGroup;
	BuildTrusteeWithSidW(&usersGroup, pUsersSid);

	// Open HKEY_LOCAL_MACHINE root key or a sub key defined by command line parameters
	HKEY hRootKey;
	std::wstring path;
	LSTATUS result;
	
	if (argc >= 2) {
		path = argv[1];
		result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &hRootKey);
	}
	else {
		path = L"";
		result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, NULL, 0, KEY_READ, &hRootKey);
	}

	// Query key and it's subkeys security descriptors recursively 
	if (result == ERROR_SUCCESS) {

		std::wcout << L"Searching for keys non-admins can create symbolic links in..." << std::endl;
		
		QueryKey(hRootKey, &usersGroup, path);
		RegCloseKey(hRootKey);
	}
	else
		std::wcout << L"Couldn't open root key" << std::endl; 

	// Close resources
	FreeSid(pUsersSid);

	return 0;
}