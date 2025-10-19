# fuzzer project for fun
## uses https://6447.lol for reference
### Fuzzer

> “Fuzzing or fuzz testing is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program. The program is then monitored for exceptions such as crashes, failing built-in code assertions, or potential memory leaks. This structure is specified, e.g., in a file format or protocol and distinguishes valid from invalid input. An effective fuzzer generates semi-valid inputs that are “valid enough” in that they are not directly rejected by the parser, but do create unexpected behaviors deeper in the program and are “invalid enough” to expose corner cases that have not been properly dealt with.” ~wikipedia

For this project you will be required to implement a **black box fuzzer**, that **given a binary containing a single vulnerability** and a file containing **one valid input to the binary**, will need to find a **valid input that causes an incorrect program state to occur** (crash, invalid memory write, heap UAF, etc).

**All binaries will read in from stdin.**

The main goal of your fuzzer should be to touch as many codepaths as possible within the binary by either mutating the supplied valid input or generating completely new input (empty files, null bytes, really big files, etc).

You are permitted to do anything you wish (other than using other fuzzers) to achieve the following functionality.

See [Fuzzer Setup](https://fuzzer.6447.lol/setup) page for details on submission expectations, and how we will setup and run your fuzzer.

## Assumptions

You can assume these facts when developing your fuzzer.

- All binaries will have a vulnerability.
- All binaries will also have an associated textfile that can be used as example input into the binary. This input will make the program function normally (return 0, not crash, no errors).
- All binaries will expect input in one of the following formats:
	- Plaintext (multiline)
	- JSON
	- XML
	- CSV
	- JPEG
	- ELF
	- PDF
- The input textfile provided will be a valid form of one of these text formats.
- Your fuzzer will have a maximum of 60 seconds per binary to find a vulnerability.
	- Your fuzzer will need to find all the possible bad files within this time range.
	- If there are 10 files, you fuzzer has 600 seconds to run. We expect you to deal with this.
- All binaries will be 64-bit Linux ELF’s.
- All vulnerabilities will result in memory corruption.

### Hints

Some hints if you are stuck on where to start.

- Try sending some known sample inputs (nothing, certain numbers, certain strings, etc)
- Try parsing the format of the input (normal text, json, etc) and send correctly formatted data with fuzzed fields.
- Try manipulating the sample input (bit flips, number replacement, etc)
- Try something awesome:D (There are no right answers)

## Something Awesome

The Something Awesome section is totally optional, and a bonus to the assignment. If you have something really cool you’d like to add to your fuzzer, let us know. The bonus marks are totally up to the discretion of the marker. This section is intentionally vague, we want you to think of cool ideas to add to your fuzzer.

You cannot get more than 100% in this assignment. The bonus 6 marks will count only for this assignment. If you get full marks, you don’t get any bonus marks.

## Documentation

Your fuzzer design and functionality (around 1-2 pages)

This section should explain, in a readable manner:

- **How your fuzzer works**. Detailed description on;
	- The different mutation strategies you use.
	- How your harness works.
	- All of your fuzzers’ capabilities
- What kinds of bugs your fuzzer can find
- What improvements can be made to your fuzzer (Be honest. We won’t dock marks for things you didn’t implement. This shows reflection and understanding)
- If you attempt any bonus marks - How your fuzzer achieves these bonus marks.
- It is insufficient if the document merely states “our fuzzer injects random values and finds bugs”. We want details that show deep understanding.

You do not have to follow any format, but this is the kind of information we expect to see in your documentation.

