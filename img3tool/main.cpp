//
//  main.cpp
//  img3tool
//
//  Created by tihmstar on 06.07.21.
//

#include <libgeneral/macros.h>
#include <libgeneral/Utils.hpp>
#include "../include/img3tool/img3tool.hpp"

#include <iostream>
#include <getopt.h>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#if HAVE_PLIST
#include <plist/plist.h>
#endif //HAVE_PLIST

#ifdef HAVE_LIBFWKEYFETCH
#include <libfwkeyfetch/libfwkeyfetch.hpp>
#endif //HAVE_LIBFWKEYFETCH

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#elif defined(HAVE_WINSOCK_H)
#include <winsock.h>
#endif

using namespace tihmstar::img3tool;

#define FLAG_ALL        (1 << 0)
#define FLAG_EXTRACT    (1 << 1)
#define FLAG_CREATE     (1 << 2)
#define FLAG_RENAME     (1 << 3)
#define FLAG_VERIFY     (1 << 4)


static struct option longopts[] = {
    { "help",           no_argument,        NULL, 'h' },
    { "create",         required_argument,  NULL, 'c' },
    { "extract",        no_argument,        NULL, 'e' },
    { "rename-payload", required_argument,  NULL, 'n' },
    { "outfile",        required_argument,  NULL, 'o' },
    { "payload",        required_argument,  NULL, 'p' },
    { "replace",        required_argument,  NULL, 'r' },
    { "type",           required_argument,  NULL, 't' },
    { "verify",         no_argument,        NULL, 'v' },
    { "iv",             required_argument,  NULL,  0  },
    { "key",            required_argument,  NULL,  0  },

#ifdef HAVE_LIBFWKEYFETCH
    { "fetch",          no_argument,        NULL, 'f' },
#endif //HAVE_LIBFWKEYFETCH
#ifdef HAVE_PLIST
    { "shsh",           required_argument,  NULL, 's' },
#endif //HAVE_PLIST
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf( "Usage: img3tool [OPTIONS] FILE\n"
            "Parses img3 files\n\n"
            "  -h, --help\t\t\tprints usage information\n"
            "  -c, --create\t<PATH>\t\tcreates img3 with raw file (last argument)\n"
            "  -e, --extract\t\t\textracts payload\n"
            "  -n, --rename-payload NAME\trename img3 payload (NAME must be exactly 4 bytes)\n"
            "  -o, --outfile\t\t\toutput path for extracting payload\n"
            "  -p, --payload\t\t\tinput img3 path for creating signed img3\n"
            "  -r, --replace\t<PATH>\t\treplace DATA in img3 (much like xpwntool's template feature)\n"
            "  -t, --type\t\t\tset type for creating IMG3 files from raw\n"
            "  -v, --verify\tverify img3\n"
            "      --iv\t\t\tIV  for decrypting payload when extracting (requires -e and -o)\n"
            "      --key\t\t\tKey for decrypting payload when extracting (requires -e and -o)\n"
#ifdef HAVE_LIBFWKEYFETCH
            "[libfwkeyfetch]\n"
#else
            "[libfwkeyfetch] (UNAVAILABLE)\n"
#endif //HAVE_LIBFWKEYFETCH
            "  -f, --fetch\t\t\tTry to get IV/KEY based on KBAG from fwkeydb\n"
#ifdef HAVE_PLIST
           "[plist]\n"
#else
           "[plist] (UNAVAILABLE)\n"
#endif //HAVE_PLIST
            "  -s, --shsh\t<PATH>\t\tFilepath for shsh\n"
            "\n"
            "Features:\n"
#ifdef HAVE_LIBFWKEYFETCH
            "libfwkeyfetch: yes\n"
#else
            "libfwkeyfetch: no\n"
#endif //HAVE_LIBFWKEYFETCH

#ifdef HAVE_PLIST
            "plist: yes\n"
#else
            "plist: no\n"
#endif //HAVE_PLIST
           );
}

tihmstar::Mem readFromFile(const char *filePath){
    int fd = -1;
    cleanup([&]{
        safeClose(fd);
    });
    struct stat st{};
    tihmstar::Mem ret;
    
    retassure((fd = open(filePath, O_RDONLY))>0, "Failed to open '%s'",filePath);
    retassure(!fstat(fd, &st), "Failed to stat file");
    ret.resize(st.st_size);
    retassure(read(fd, ret.data(), ret.size()) == ret.size(), "Failed to read file");
    return ret;
}

#ifdef HAVE_PLIST
plist_t readPlistFromFile(const char *filePath){
    int fd = -1;
    char *buf = NULL;
    cleanup([&]{
        safeFree(buf);
        safeClose(fd);
    });
    size_t bufSize = 0;
    struct stat st = {};
    retassure((fd = open(filePath, O_RDONLY)) != -1, "Failed to open '%s'",filePath);
    retassure(!fstat(fd, &st), "Failed to stat file");
    retassure(buf = (char*)malloc(bufSize = st.st_size), "Failed to malloc buf");
    retassure(read(fd, buf, bufSize) == bufSize, "Failed to read file");
    plist_t plist = NULL;
    plist_from_memory(buf, (uint32_t)bufSize, &plist, NULL);
    return plist;
}
#endif //HAVE_PLIST

void saveToFile(const char *filePath, const void *buf, size_t bufSize){
    FILE *f = NULL;
    cleanup([&]{
        if (f) {
            fclose(f);
        }
    });
    
    if (strcmp(filePath, "-") == 0) {
        write(STDERR_FILENO, buf, bufSize);
    }else{
        retassure(f = fopen(filePath, "wb"), "failed to create file");
        retassure(fwrite(buf, 1, bufSize, f) == bufSize, "failed to write to file");
    }
}

MAINFUNCTION
int main_r(int argc, const char * argv[]) {
    info("%s",version());

    const char *lastArg = NULL;
    const char *outFile = NULL;
    const char *img3Type = NULL;
    const char *replaceTemplateFilePath = NULL;
    const char *decryptIv = NULL;
    const char *decryptKey = NULL;
    const char *shshFile = NULL;
    const char *payloadimg3 = NULL;

    int optindex = 0;
    int opt = 0;
    long flags = 0;
    bool fetchKeys = false;

    while ((opt = getopt_long(argc, (char* const *)argv, "hc:efn:o:p:r:s:t:v", longopts, &optindex)) >= 0) {
        switch (opt) {
            case 0: //long opts
            {
                std::string curopt = longopts[optindex].name;
                
                if (curopt == "iv") {
                    decryptIv = optarg;
                }else if (curopt == "key") {
                    decryptKey = optarg;
                }
                break;
            }
            case 'h':
                cmd_help();
                return 0;
            case 'c':
                flags |= FLAG_CREATE;
                retassure(!(flags & FLAG_EXTRACT) && !replaceTemplateFilePath, "Invalid command line arguments. can't extract and create at the same time");
                retassure(!outFile, "Invalid command line arguments. outFile already set!");
                outFile = optarg;
                break;
            case 'e':
                retassure(!(flags & FLAG_CREATE) && !replaceTemplateFilePath, "Invalid command line arguments. can't extract and create at the same time");
                flags |= FLAG_EXTRACT;
                break;
            case 'f':
                fetchKeys = true;
                break;
            case 'n': //rename-payload
                retassure(!img3Type, "Invalid command line arguments. im4pType already set!");
                img3Type = optarg;
                flags |= FLAG_RENAME;
                break;
            case 'o':
                retassure(!outFile, "Invalid command line arguments. outFile already set!");
                outFile = optarg;
                break;
            case 'p':
                payloadimg3 = optarg;
                break;
            case 'r':
                retassure(!(flags & (FLAG_CREATE | FLAG_EXTRACT)), "Invalid command line arguments. can't replace, extract and create at the same time");
                replaceTemplateFilePath = optarg;
                break;
            case 't':
                retassure(!img3Type, "Invalid command line arguments. img3Type already set!");
                img3Type = optarg;
                break;
#ifdef HAVE_PLIST
            case 's':
                shshFile = optarg;
                break;
#endif //HAVE_PLIST
            case 'v':
                flags |= FLAG_VERIFY;
                break;

            default:
                cmd_help();
                return -1;
        }
    }
#ifdef HAVE_LIBFWKEYFETCH
    tihmstar::libfwkeyfetch::fw_key fwKey = {};
#endif //HAVE_LIBFWKEYFETCH

    if (outFile && strcmp(outFile, "-") == 0) {
        int s_out = -1;
        int s_err = -1;
        cleanup([&]{
            safeClose(s_out);
            safeClose(s_err);
        });
        s_out = dup(STDOUT_FILENO);
        s_err = dup(STDERR_FILENO);
        dup2(s_out, STDERR_FILENO);
        dup2(s_err, STDOUT_FILENO);
    }

    if (argc-optind == 1) {
        argc -= optind;
        argv += optind;
        lastArg = argv[0];
    }else{
        if (!(flags & FLAG_CREATE)) {
            cmd_help();
            return -2;
        }
    }
    
    tihmstar::Mem workingBuf;

    if (lastArg) {
        if (strcmp(lastArg, "-") == 0){
            char cbuf[0x1000] = {};
            ssize_t didRead = 0;
            
            while ((didRead = read(STDIN_FILENO, cbuf, sizeof(cbuf))) > 0) {
                workingBuf.append(cbuf, didRead);
            }
            
        }else{
            workingBuf = tihmstar::readFile(lastArg);
        }
    }

    if (flags & FLAG_EXTRACT) {
        retassure(outFile, "Outfile required for operation");
        const char *compression = NULL;
        if (fetchKeys && (!decryptIv || !strlen(decryptIv)) && (!decryptKey || !strlen(decryptKey))) {
#ifndef HAVE_LIBFWKEYFETCH
            reterror("Compiled without libfwkeyfetch");
#else
            for (int i=1; i>0; i++) {
                std::string kbagstr;
                try {
                    tihmstar::Mem kbag = getKBAG(workingBuf.data(),workingBuf.size(), i);
                    for (int z=0; z<kbag.size(); z++) {
                        char cur[4] = {};
                        snprintf(cur, sizeof(cur), "%02x",kbag.data()[z]);
                        kbagstr += cur;
                    }
                } catch (tihmstar::exception &e) {
#ifdef DEBUG
                    e.dump();
#endif
                    warning("Failed to get KBAG at index %d, falling back to extraction without keys!",i);
                    goto failedToFindKeys;
                }
                try {
                    info("Fetching keys for KBAG %d",i);
                    fwKey = tihmstar::libfwkeyfetch::getFirmwareKeyForKBAG(kbagstr);
                } catch (tihmstar::exception &e) {
#ifdef DEBUG
                    e.dump();
#endif
                    error("Failed to fetch IV/Key for KBAG %d (%s), retrying with next...",i,kbagstr.c_str());
                    continue;
                }
                decryptIv = fwKey.iv;
                decryptKey = fwKey.key;
                info("Found IV: %s KEY: %s", decryptIv, decryptKey);
                break;
            }
#endif
        failedToFindKeys:;
        }
        auto outdata = getPayloadFromIMG3(workingBuf.data(),workingBuf.size(), decryptIv, decryptKey);
        saveToFile(outFile, outdata.data(), outdata.size());
        if (compression) {
            info("Extracted (and uncompressed %s) IMG3 payload to %s",compression,outFile);
        }else{
            info("Extracted IMG3 payload to %s",outFile);
        }
    }else if (flags & FLAG_CREATE) {
        retassure(outFile, "Outfile required for operation");
        retassure(img3Type, "img3Type required for operation");
        tihmstar::Mem img3;
        if (payloadimg3) {
            img3 = readFromFile(payloadimg3);
        }else{
            img3 = getEmptyIMG3Container(htonl(*(uint32_t*)img3Type));
            img3 = appendPayloadToIMG3(img3, 'DATA', workingBuf);
        }
        if (shshFile) {
#ifdef HAVE_PLIST
            plist_t p_shsh = readPlistFromFile(shshFile);
            cleanup([&]{
                safeFreeCustom(p_shsh, plist_free);
            });
            img3 = signIMG3WithSHSH(img3.data(), img3.size(), p_shsh);
#else
            error("Compiled without PLIST. Can't make signed img3");
            return -1;
#endif
        }

        saveToFile(outFile, img3.data(), img3.size());
        info("Created IMG3 file at %s",outFile);
    }else if (flags & FLAG_RENAME){
        retassure(outFile, "outputfile required");

        auto img3 = renameIMG3(workingBuf.data(), workingBuf.size(), img3Type);
        saveToFile(outFile, img3.data(), img3.size());
        info("Saved new renamed IMG3 to %s",outFile);
    } else if (replaceTemplateFilePath) {
        retassure(outFile, "Outfile required for operation");
        tihmstar::Mem templateFile = readFromFile(replaceTemplateFilePath);
        auto img3 = replaceDATAinIMG3(templateFile, workingBuf);
        img3 = removeTagFromIMG3(img3.data(), img3.size(), 'KBAG');
        saveToFile(outFile, img3.data(), img3.size());
        info("Created IMG3 file at %s",outFile);
    }else if (flags & FLAG_VERIFY){
        info("Verifying IMG3 file");
        bool isSigned = false;
        if (shshFile) {
#ifdef HAVE_PLIST
            plist_t p_shsh = readPlistFromFile(shshFile);
            cleanup([&]{
                safeFreeCustom(p_shsh, plist_free);
            });
            isSigned = verifySignedIMG3FileForSHSH(workingBuf.data(), workingBuf.size(), p_shsh);
#endif
            info("IMG3 file signature is %s for SHSH",isSigned ? "VALID" : "NOT valid");
        }else{
            isSigned = verifySignedIMG3File(workingBuf.data(), workingBuf.size());
            info("IMG3 file signature is %s",isSigned ? "VALID" : "NOT valid");
        }
        return isSigned ? 0 : 1;
    }else{
        //print
        printIMG3(workingBuf.data(), workingBuf.size());
    }
    
    
    return 0;
}
