#pragma once

//used to ensure program has valid sig and isn't corrupted
#define SIGNATURE 0x13131313

//so for some reason my defines weren't null terminated,
//so in cryptor.cpp there's some tomfoolery where i have to 
//add a null terminator to the string. remember to free them yo
#define CODE_SEG_NAME ".rofl"
//nevermind, it was just me. turns out windows PIMAGE_SECTION_HEADER 
//defines the name of the section as an 8 BYTE array. which means that 
//8th byte was being overwritten by me, instead of being a null terminator
//leaving in the previous comments for education :)
#define CODE_SEG_LINK "/SECTION:.rofl,ER"
#define STUB_SEG_NAME ".stoob"
