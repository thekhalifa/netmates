/**
 * @file nm-appgui.c
 * Main for the GTK application, instead of cpp ifdefs
 *
 * SPDX-License-Identifier: GPL-3.0
 */
#include "nm-appwindow.h"

int main(int argc, char **argv)
{
    return init_application(argc, argv);
}

