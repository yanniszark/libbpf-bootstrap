#ifndef __CLASSDEF_H__
#define __CLASSDEF_H__

class X {
    public:
        X() {}

        int getX(void) { return x;}
        void setX(int n) { x = n; }

        int getP(void) { return *p; }
        void setP(int *n) { p = n; }
    private:
        int x;
        int *p;
};

#endif
