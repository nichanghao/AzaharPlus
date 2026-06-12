#pragma once

#include <string>

namespace Core {

int exportZipPass(std::string path);

int importZipPass(std::string path);

int clearStreetPassConfig();

} // namespace Core
