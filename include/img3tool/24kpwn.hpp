//
//  24kpwn.h
//  img3tool
//
//  Created by erd on 18.03.26.
//

#ifndef x24kpwn_h
#define x24kpwn_h

#include <libgeneral/Mem.hpp>

namespace tihmstar {
namespace img3tool {

tihmstar::Mem do24kpwn(const void *buf, size_t size, uint32_t cpid = 0);

}
}


#endif /* x24kpwn_h */
