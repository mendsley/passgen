#if defined(_WIN32)
#	define _CRT_SECURE_NO_WARNINGS
#	define WIN32_LEAN_AND_MEAN
#	define NOMINMAX
#	include <Windows.h>
#	include <bcrypt.h>
#	include <stdint.h>
#	define secure_clear(dest, size) SecureZeroMemory((dest), (size))
	static int gen_random(void* dest, uint32_t size) {
		NTSTATUS result = BCryptGenRandom(
				  nullptr
				, (PUCHAR)dest
				, size
				, BCRYPT_USE_SYSTEM_PREFERRED_RNG
		);
		if (!BCRYPT_SUCCESS(result)) {
			return result;
		}

		return 0;
	}
#	pragma comment(lib, "Bcrypt")
#elif defined(__linux__)
#	include <errno.h>
#	include <sys/random.h>
#	include <stdint.h>
#	include <string.h>
#	define secure_clear(dest, size) explicit_bzero((dest), (size))
	static int gen_random(void* dest, uint32_t size) {
		uint8_t* dest_bytes = (uint8_t*)dest;
		while (size > 0) {
			ssize_t result = getrandom(dest_bytes, size, GRND_NONBLOCK);
			if (-1 == result) {
				return errno;
			}

			dest_bytes += result;
			size -= result;
		}

		return 0;
	}
#elif defined(__APPLE__)
#	define __STDC_WANT_LIB_EXT1__ 1
#	include <stdint.h>
#	include <string.h>
#	include <strings.h>
#	include <stdlib.h>
#	define secure_clear(dest, size) memset_s((void*)(dest), (size), 0, (size))
	static int gen_random(void* dest, uint32_t size) {
		arc4random_buf(dest, size);
		return 0;
	}
#else
#	error Unknown platform. Need secure_clear
#	error Unknown platform, Need gen_random
#endif

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <vector>

int main(int argc, char* argv[]) {

	uint32_t password_len = 32;
	bool alnum_only = false;
	bool allow_ambiguous_chars = false;
	char* characters_to_remove = nullptr;

	// parse command line arguments
	for (int ii = 1; ii != argc; ++ii) {
		if (0 == strcmp(argv[ii], "-alnum")) {
			alnum_only = true;
			memmove(argv[ii], argv[ii+1], sizeof(char*)*(argc-ii-1));
			--ii;
			--argc;
		} else if (0 == strcmp(argv[ii], "-ambiguous")) {
			allow_ambiguous_chars = true;
			memmove(argv[ii], argv[ii+1], sizeof(char*)*(argc-ii-1));
			--ii;
			--argc;
		} else if (0 == strcmp(argv[ii], "-rm")) {
			if (ii == argc-1) {
				fprintf(stderr, "-rm requires an argument for characters to exclude\n");
				return -1;
			}
			size_t num_of_characters_to_remove = strlen(argv[ii+1]);
			characters_to_remove = static_cast<char*>(calloc(num_of_characters_to_remove + 1, 1));
			memcpy(characters_to_remove, argv[ii+1], num_of_characters_to_remove);
			memmove(argv[ii], argv[ii+2], sizeof(char*)*(argc-ii-2));
			ii -= 2;
			argc -= 2;
		}
	}

	if (argc > 1) {
		uint32_t  value;
		if (1 == sscanf(argv[1], "%u", &value)) {
			password_len = value;
		} else {
			fprintf(stderr, "Failed to convert `%s` to a number\n", argv[1]);
			return -1;
		}

		if (password_len > 2048) {
			fprintf(stderr, "Password seems to be too large: %u\n", password_len);
			return -1;
		}
	}

	uint8_t random_buffer[64];
	uint32_t random_buffer_index = sizeof(random_buffer);

	// generate character
	constexpr char ALNUM[] = {
		  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'
		, 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
		, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M'
		, 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
		, '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
	};

	constexpr char SPECIAL[] = {
		'!', '@', '#', '$', '%', '^', '*', '(', ')', '-', '_', '+'
		, '~', '`', '<', '>', '"', '[', ']', '{', '}', ';', ':', '\''
	};

	// build available character set
	std::vector<char> available_characters;
	available_characters.reserve(sizeof(ALNUM) + sizeof(SPECIAL));
	available_characters.insert(available_characters.end(), ALNUM, ALNUM + sizeof(ALNUM));
	if (!alnum_only) {
		available_characters.insert(available_characters.end(), SPECIAL, SPECIAL + sizeof(SPECIAL));
	}

	if (!allow_ambiguous_chars) {
		std::vector<char>::iterator end = std::remove_if(available_characters.begin(), available_characters.end(), [](const char c) {
			switch (c) {
			case 'l':
			case '1':
			case 'I':
			case '|':
			case 'O':
			case '0':
				return true;

			default:
				return false;
			}
		});
		available_characters.erase(end, available_characters.end());
	}

	if (characters_to_remove) {
		std::vector<char>::iterator end = std::remove_if(available_characters.begin(), available_characters.end(), [characters_to_remove](const char c) {
			return nullptr != strchr(characters_to_remove, c);
		});
		available_characters.erase(end, available_characters.end());
	}

	if (available_characters.empty()) {
		fputs("No available character set. Aborting.\n", stderr);
		return -1;
	}

	char* alpha = new char[password_len+1u];
	for (uint32_t ii = 0; ii != password_len; ++ii) {

		uint32_t char_index = 0;
		for (;;) {

			// fill random buffer if needed
			if (random_buffer_index >= sizeof(random_buffer)) {
				secure_clear(random_buffer, sizeof(random_buffer));
				int result = gen_random(random_buffer, sizeof(random_buffer));
				if (0 != result) {
					secure_clear(alpha, sizeof(alpha));
					fprintf(stderr, "Failed to generate random buffer: %d\n"
							, result
					);
					return -1;
				}

				random_buffer_index = 0;
			}

			const uint8_t RANGE = 0xFF - static_cast<int>(available_characters.size()) % 0xFF;

			uint8_t value = random_buffer[random_buffer_index];
			++random_buffer_index;
			if (value >= RANGE) {
				continue;
			}

			char_index = value % static_cast<int>(available_characters.size());
			break;
		}

		alpha[ii] = available_characters[char_index];
	}
	alpha[password_len] = '\0';

	printf("%s\n", alpha);
	secure_clear(random_buffer, sizeof(random_buffer));
	secure_clear(alpha, password_len+1u);
	delete[] alpha;
}
