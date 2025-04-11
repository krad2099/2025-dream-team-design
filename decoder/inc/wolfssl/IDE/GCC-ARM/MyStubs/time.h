#ifndef _MY_STUB_TIME_H_
#define _MY_STUB_TIME_H_

typedef long time_t;

static inline time_t time(time_t *t) {
    if (t) *t = 0;
    return 0;
}

#endif /* _MY_STUB_TIME_H_ */
