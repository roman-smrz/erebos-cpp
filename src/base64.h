#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace { namespace base64 {

	const static char encodeLookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const static char padCharacter = '=';

	std::string encode(const std::vector<uint8_t> & input)
	{
		std::string encoded;
		encoded.reserve(((input.size()/3) + (input.size() % 3 > 0)) * 4);
		uint32_t temp;
		auto cursor = input.begin();
		for (size_t i = 0; i < input.size() / 3; i++)
		{
			temp  = (*cursor++) << 16; // Convert to big endian
			temp += (*cursor++) << 8;
			temp += (*cursor++);
			encoded.append(1, encodeLookup[(temp & 0x00FC0000) >> 18]);
			encoded.append(1, encodeLookup[(temp & 0x0003F000) >> 12]);
			encoded.append(1, encodeLookup[(temp & 0x00000FC0) >> 6 ]);
			encoded.append(1, encodeLookup[(temp & 0x0000003F)      ]);
		}
		switch (input.size() % 3)
		{
		case 1:
			temp  = (*cursor++) << 16; // Convert to big endian
			encoded.append(1, encodeLookup[(temp & 0x00FC0000) >> 18]);
			encoded.append(1, encodeLookup[(temp & 0x0003F000) >> 12]);
			encoded.append(2, padCharacter);
			break;
		case 2:
			temp  = (*cursor++) << 16; // Convert to big endian
			temp += (*cursor++) << 8;
			encoded.append(1, encodeLookup[(temp & 0x00FC0000) >> 18]);
			encoded.append(1, encodeLookup[(temp & 0x0003F000) >> 12]);
			encoded.append(1, encodeLookup[(temp & 0x00000FC0) >> 6 ]);
			encoded.append(1, padCharacter);
			break;
		}
		return encoded;
	}

	std::vector<uint8_t> decode(const std::string & input)
	{
		if (input.length() % 4) // Sanity check
			throw std::runtime_error("Non-Valid base64!");

		size_t padding = 0;
		if (input.length()) {
			if (input[input.length() - 1] == padCharacter)
				padding++;
			if (input[input.length() - 2] == padCharacter)
				padding++;
		}

		// Setup a vector to hold the result
		std::vector<uint8_t> decoded;
		decoded.reserve(((input.length()/4)*3) - padding);
		uint32_t temp = 0; // Holds decoded quanta
		auto cursor = input.begin();
		while (cursor < input.end())
		{
			for (size_t quantumPosition = 0; quantumPosition < 4; quantumPosition++)
			{
				temp <<= 6;
				if      (*cursor >= 0x41 && *cursor <= 0x5A)   // This area will need tweaking if
					temp |= *cursor - 0x41;                // you are using an alternate alphabet
				else if (*cursor >= 0x61 && *cursor <= 0x7A)
					temp |= *cursor - 0x47;
				else if (*cursor >= 0x30 && *cursor <= 0x39)
					temp |= *cursor + 0x04;
				else if (*cursor == 0x2B)
					temp |= 0x3E; // change to 0x2D for URL alphabet
				else if (*cursor == 0x2F)
					temp |= 0x3F; // change to 0x5F for URL alphabet
				else if (*cursor == padCharacter) // pad
				{
					switch (input.end() - cursor)
					{
					case 1: //One pad character
						decoded.push_back((temp >> 16) & 0x000000FF);
						decoded.push_back((temp >> 8 ) & 0x000000FF);
						return decoded;
					case 2: //Two pad characters
						decoded.push_back((temp >> 10) & 0x000000FF);
						return decoded;
					default:
						throw std::runtime_error("Invalid Padding in Base 64!");
					}
				}  else
					throw std::runtime_error("Non-Valid Character in Base 64!");
				cursor++;
			}
			decoded.push_back((temp >> 16) & 0x000000FF);
			decoded.push_back((temp >> 8 ) & 0x000000FF);
			decoded.push_back((temp      ) & 0x000000FF);
		}
		return decoded;
	}

} }
