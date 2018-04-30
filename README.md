Gentle peruser, it's in the code, with my best attempted guidance for less
advanced (but truly hard-working) in the comments.

To understand, and maybe also to use the code, there may be some figuring out
that's needed on your part.

All git versions included may be needed, and useful for some of the stages.

Look up the chread_tcp.pl. The initial version is actually Chaosreader. And
then follow my transforming of it, the debugging of it, and my starting to
write stream-cont.pl.

The stream-cont.pl does extract pretty much all files from TCP SSL-streams (and
sure equally well plain TCP streams, but who uses plain browsing anymore?).

I first trace and screen my stay online with my:

https://github.com/miroR/uncenz

Afterwards, if I analyze a whole bunch I may run PCAPs-work-prep.sh from my

https://github.com/miroR/workPCAPs

which runs tshark-hosts-conv and tshark-streams (usually non-interactively).

And this stream-cont was sorely missing in my toolbox.
