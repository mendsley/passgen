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
#else
#	error Unknown platform. Need secure_clear
#	error Unknown platform, Need gen_random
#endif

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {

	uint32_t password_len = 32;
	bool alnum_only = false;

	// parse command line arguments
	for (int ii = 1; ii != argc; ++ii) {
		if (0 == strcmp(argv[ii], "-alnum")) {
			alnum_only = true;
			memmove(argv[ii], argv[ii+1], sizeof(char*)*(argc-ii-1));
			--ii;
			--argc;
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
	constexpr char CHARACTERS[] = {
		  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'
		, 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
		, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M'
		, 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
		, '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
		, '!', '@', '#', '$', '%', '^', '*', '(', ')', '-', '_', '+'
		, '~', '`', '<', '>', '"', '[', ']', '{', '}', ';', ':', '\''
	};
	char* alpha = new char[password_len+1u];
	for (uint32_t ii = 0; ii != password_len; ++ii) {

		const bool needs_alnum = false
			|| (ii == 0 )
			|| (ii == password_len-1)
			|| alnum_only
			;

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

			constexpr uint8_t RANGE = 0xFF - sizeof(CHARACTERS) % 0xFF;

			uint8_t value = random_buffer[random_buffer_index];
			++random_buffer_index;
			if (value >= RANGE) {
				continue;
			}

			char_index = value % sizeof(CHARACTERS);

			if (needs_alnum && !isalnum(CHARACTERS[char_index])) {
				continue;
			}

			break;
		}

		alpha[ii] = CHARACTERS[char_index];
	}
	alpha[password_len] = '\0';

	printf("%s\n", alpha);
	secure_clear(random_buffer, sizeof(random_buffer));
	secure_clear(alpha, password_len+1u);
	delete[] alpha;
}
