workspace "passgen"
	location ".visualc"

	platforms "x64"
	configurations {"Debug", "Release"}

	symbols "Full"
	debugformat "c7"
	characterset "Unicode"

	flags "FatalWarnings"

	filter "Release"
		optimize "Full"

project "passgen"
	kind "ConsoleApp"
	language "C++"

	files "main.cpp"
