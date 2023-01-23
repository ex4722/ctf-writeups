# ZeroTo7Solves

A couple months ago I came across this blog post https://blog.kylebot.net/2022/10/16/CVE-2022-1786/ and after this conversation with out team captian I decided to write a kernel challenge for IdekCTF.

With only knowleadge of the kernel from Pwn.College and very bad C skills I decided to try to learn enought about kernel exploitation that I could write my own challenge. 

During my attempts to learn kernel exploitation I noticed a lack of recent resources in english so I decied to document this entire journey

## Pwn College
My first interactions with the kernel was through Pwn College's baby kernel modules. https://dojo.pwn.college/archive-cse466/kernel Through these challenges I learned that the kernel is not that scary as its just a giant binary thats very complicated. Through this module I learned the basics of interacting with the kernel through Ioctl and character devices, kernel shellcoding and the win() functions of the kernel.
Overall this was a great first interaction with the kernel as the enviorment was all setup so their was little friction with settign up the enviorment

## Family Recipies from TeamItaly CTF 2022
During this CTF I had attempted to solve this challenge with little luck. Months after the CTF I decided to revisit the challenge and ended up following the authors writeup to solve this challenge. 
I could not spot any of the bugs for the life of me and decided to just peek at the authors writeup. I am very glad I did as I doubt I would have been able to spot it. 
Overall this challenge contained a lot fo addition informatino like finding offsets in structs, common ways to turn arb read write into code exection and kernel configurations. 
tl;dr for this challenge is an integer overflow that allows for a size of 0 to be passed into realloc resulting in free being called instead malloc resultingin a use after free.


## Kstack
Found this challenge on a "easy" kernel challenges page, it was not easy at all...
This challenge was like Family Recipies but without the training wheels. This exploit taught me the ideas behind makign races 100% stable my pausing the kernel at spots using using user controlled code. This exact technique is no longer applicabel in newer kernel versions but the idea remains the same. 
In particular this challenge used signal handlers to hang the kernel at specifc spots. The idea is that copy to and from user both need touch userspace memory when they copy. So if we have a race that we want to win and theirs a copy after our conditon is triggered we can use userfaultfd to hold this. By placing two pages back to back and marking one as read write and one as non writeable we can cause a segfault once the kernel tried to copy code to us. Then we can register a handler for this segfault allowing us to execute more code before releasing that kernel thread. 
