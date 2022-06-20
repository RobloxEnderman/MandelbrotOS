#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mandelbrot.h>
#include <sys/mman.h>

uint16_t width;
uint16_t height;
uint32_t *framebuffer;

extern uint64_t intsyscall(uint64_t call, uint64_t arg1, uint64_t arg2,
                           uint64_t arg3, uint64_t arg4, uint64_t arg5);

typedef struct pixel {
  uint8_t blue;
  uint8_t green;
  uint8_t red;
  uint8_t unused;
} pixel_t;

int floor(double x) {
  int xi = (int)x;
  return x < xi ? xi - 1 : xi;
}

pixel_t hsv2rgb(float h, float s, float v) {
  int i;
  float f, p, q, t;

  while (h > 360)
    h -= 360;

  if (s == 0) {
    // achromatic (grey)
    return (pixel_t){
      .red = s,
      .green = s,
      .blue = s,
    };
  }
  h /= 60; // sector 0 to 5
  i = floor(h);
  f = h - i; // factorial part of h
  p = v * (1 - s);
  q = v * (1 - s * f);
  t = v * (1 - s * (1 - f));
  switch (i) {
    case 0:
      return (pixel_t){
        .red = v * 255,
        .green = t * 255,
        .blue = p * 255,
      };
      break;
    case 1:
      return (pixel_t){
        .red = q * 255,
        .green = v * 255,
        .blue = p * 255,
      };
      break;
    case 2:
      return (pixel_t){
        .red = p * 255,
        .green = v * 255,
        .blue = t * 255,
      };
      break;
    case 3:
      return (pixel_t){
        .red = p * 255,
        .green = q * 255,
        .blue = v * 255,
      };
      break;
    case 4:
      return (pixel_t){
        .red = t * 255,
        .green = p * 255,
        .blue = v * 255,
      };
      break;
    default: // case 5:
      return (pixel_t){
        .red = v * 255,
        .green = p * 255,
        .blue = q * 255,
      };
      break;
  }
}

static inline double cos(double x) {
  register double val;
  asm volatile("fcos\n" : "=t"(val) : "0"(x));
  return val;
}

static inline double sin(double x) {
  register double val;
  asm volatile("fsin\n" : "=t"(val) : "0"(x));
  return val;
}

static inline double tan(double x) { return sin(x) / cos(x); }

void draw_line(int64_t x0, int64_t y0, int64_t x1, int64_t y1,
               uint32_t colour) {
  int deltax = x1 - x0;
  int deltay = y1 - y0;
  int y = 0;
  int x = 0;
  int sdx = (deltax < 0) ? -1 : 1; // sign of deltax (e.g. +ve or -ve)
  int sdy = (deltay < 0) ? -1 : 1;

  deltax = sdx * deltax + 1;
  deltay = sdy * deltay + 1; // (-1*-6)+1) = 7

  int px = x0; // starting point (x0,y0)
  int py = y0;

  if (deltax >= deltay) {
    for (x = 0; x < deltax; x++) {
      framebuffer[px + (py * width)] = colour;
      y += deltay;     // y=mx... but if y starts at y0
      if (y >= deltax) // m=deltax/deltay  and py+=m
      {                // if the numberator is greator than the denomiator
        y -= deltax;   // we increment, and subract from the numerator.
        py += sdy;
      }
      px += sdx; // x is going from x0 to x1... we just increment as we
    }
  } else {
    for (y = 0; y < deltay; y++) {
      framebuffer[px + (py * width)] = colour;

      x += deltax;

      if (x >= deltay) {
        x -= deltay;
        px += sdx;
      }
      py += sdy;
    }
  }
}

uint32_t rgb2hex(pixel_t pix) {
  return (pix.red << 16) + (pix.green << 8) + pix.blue;
}

#define pi 3.141592

double pow(double base, int exponent) {
  double result = 1;
  while (exponent--)
    result *= base;
  return result;
}

#include <stdio.h>

void main() {
  /* char msg[] = "In ring 3! Got a PID of  \n"; */
  /* size_t len = strlen(msg); */
  /* msg[len - 3] = val + '0'; */

  /* while (1) */
  /* ; */

  size_t fd = open("/dev/fb0", O_RDWR);

  width = ioctl(fd, IOCTL_FBDEV_GET_WIDTH, 0);
  height = ioctl(fd, IOCTL_FBDEV_GET_HEIGHT, 0);
  size_t bpp = ioctl(fd, IOCTL_FBDEV_GET_BPP, 0);

  framebuffer = (uint32_t *)mmap(NULL, width * height * (bpp / 8),
                                 PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  for (size_t i = 0; i < width * height; i++)
    framebuffer[i] = 0xffffff;

  for (size_t i = 0; i < width; i++)
    framebuffer[(height / 2) * width + i] ^= 0xffffff;

  for (size_t i = 0; i < height; i++)
    framebuffer[(width / 2) + (i * width)] ^= 0xffffff;

  /* uint8_t thing1[2]; */
  /* uint8_t thing2[2]; */

  /* intsyscall(SYSCALL_EXEC, (uint64_t) "new task", (uint64_t) "/prog/trig", */
  /* (uint64_t)thing1, (uint64_t)thing2, 0); */

  /* double amp = 50; */
  /* double ang_inc = .5; */

  /* double angle = 0; */

  /* int64_t prev_y = (height / 2); */

  /* for (size_t x = 0; x < width; x++, angle += ang_inc) { */
  /* double yo = amp * tan((angle * 3.14159) / 180); */
  /* int64_t y = ((double)height / 2) - yo; */

  /* if (y > height) { */
  /* y = height - 1; */
  /* prev_y = height - 1; */
  /* } else if (y < 0) { */
  /* y = 0; */
  /* prev_y = 0; */
  /* } */

  /* if (prev_y > y) */
  /* draw_line(x, y, x - 1, prev_y, */
  /* rgb2hex(hsv2rgb(((double)x / (double)width) * 360, 1, 1))); */

  /* prev_y = y; */

  /* for (volatile size_t i = 0; i < 5000000; i++) */
  /* asm volatile("nop"); */
  /* } */

  while (1) {
    double amp = 300;
    double ang_inc = 1;

    double angle = 0;

    int64_t prev_y1 =
      (height / 2) - (int64_t)(amp * sin((angle * 3.14159) / 180));
    int64_t prev_y2 =
      (height / 2) - (int64_t)(amp * sin(((angle + 120) * 3.14159) / 180));
    int64_t prev_y3 =
      (height / 2) - (int64_t)(amp * sin(((angle + 240) * 3.14159) / 180));

    for (size_t x = 0; x < width; x++, angle += ang_inc) {
      double yo = amp * sin((angle * 3.14159) / 180);
      int64_t y = ((double)height / 2) - yo;

      draw_line(
        x, y, (x > 0) ? x - 1 : 0, prev_y1,
        rgb2hex(hsv2rgb((((double)x / (double)width) * 360 + 0), 1, 1)));

      prev_y1 = y;

      yo = amp * sin(((angle + 120) * 3.14159) / 180);
      y = ((double)height / 2) - yo;

      draw_line(
        x, y, (x > 0) ? x - 1 : 0, prev_y2,
        rgb2hex(hsv2rgb((((double)x / (double)width) * 360 + 120), 1, 1)));

      prev_y2 = y;

      yo = amp * sin(((angle + 240) * 3.14159) / 180);
      y = ((double)height / 2) - yo;

      draw_line(
        x, y, (x > 0) ? x - 1 : 0, prev_y3,
        rgb2hex(hsv2rgb((((double)x / (double)width) * 360 + 240), 1, 1)));

      prev_y3 = y;

      for (volatile size_t i = 0; i < 7000000; i++)
        asm volatile("nop");
    }
  }
}
