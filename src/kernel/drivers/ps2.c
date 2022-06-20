#include <asm.h>
#include <drivers/apic.h>
#include <drivers/ps2.h>
#include <pipe/pipe.h>
#include <printf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/irq.h>
#include <tasking/scheduler.h>

#define PS2_KBD_MAX_CODE 0x57

#define PS2_CMD_PORT 0x64
#define PS2_DATA_PORT 0x60

#define PS2_KBD_BUF_LEN 0x4000

#define PS2_KEY_MAX_CODE 0x57
#define PS2_KEY_CAPSLOCK 0x3a
#define PS2_KEY_LEFT_ALT 0x38
#define PS2_KEY_LEFT_ALT_REL 0xb8
#define PS2_KEY_RIGHT_SHIFT 0x36
#define PS2_KEY_LEFT_SHIFT 0x2a
#define PS2_KEY_RIGHT_SHIFT_REL 0xb6
#define PS2_KEY_LEFT_SHIFT_REL 0xaa
#define PS2_KEY_CTRL 0x1d
#define PS2_KEY_CTRL_REL 0x9d

static pipe_t kbd_pipe;
static int8_t mouse_keys[3] = {0};
static uint8_t mouse_cycle = 0;

static int capslock_active = 0;
static int shift_active = 0;
static int ctrl_active = 0;
static int alt_active = 0;
static int extra_scancodes = 0;

static char ps2_scandcodes_capslock[] = {
  '\0', '\e', '1',  '2',  '3',  '4',  '5',  '6',  '7',  '8', '9', '0',
  '-',  '=',  '\b', '\t', 'Q',  'W',  'E',  'R',  'T',  'Y', 'U', 'I',
  'O',  'P',  '[',  ']',  '\n', '\0', 'A',  'S',  'D',  'F', 'G', 'H',
  'J',  'K',  'L',  ';',  '\'', '`',  '\0', '\\', 'Z',  'X', 'C', 'V',
  'B',  'N',  'M',  ',',  '.',  '/',  '\0', '\0', '\0', ' '};

static char ps2_scandcodes_shift[] = {
  '\0', '\e', '!',  '@',  '#',  '$',  '%',  '^',  '&',  '*', '(', ')',
  '_',  '+',  '\b', '\t', 'Q',  'W',  'E',  'R',  'T',  'Y', 'U', 'I',
  'O',  'P',  '{',  '}',  '\n', '\0', 'A',  'S',  'D',  'F', 'G', 'H',
  'J',  'K',  'L',  ':',  '"',  '~',  '\0', '|',  'Z',  'X', 'C', 'V',
  'B',  'N',  'M',  '<',  '>',  '?',  '\0', '\0', '\0', ' '};

static char ps2_scandcodes_shift_capslock[] = {
  '\0', '\e', '!',  '@',  '#',  '$',  '%',  '^',  '&',  '*', '(', ')',
  '_',  '+',  '\b', '\t', 'q',  'w',  'e',  'r',  't',  'y', 'u', 'i',
  'o',  'p',  '{',  '}',  '\n', '\0', 'a',  's',  'd',  'f', 'g', 'h',
  'j',  'k',  'l',  ':',  '"',  '~',  '\0', '|',  'z',  'x', 'c', 'v',
  'b',  'n',  'm',  '<',  '>',  '?',  '\0', '\0', '\0', ' '};

static char ps2_scancodes_norm[] = {
  '\0', '\e', '1',  '2',  '3',  '4',  '5',  '6',  '7',  '8', '9', '0',
  '-',  '=',  '\b', '\t', 'q',  'w',  'e',  'r',  't',  'y', 'u', 'i',
  'o',  'p',  '[',  ']',  '\n', '\0', 'a',  's',  'd',  'f', 'g', 'h',
  'j',  'k',  'l',  ';',  '\'', '`',  '\0', '\\', 'z',  'x', 'c', 'v',
  'b',  'n',  'm',  ',',  '.',  '/',  '\0', '\0', '\0', ' '};

void ps2_wait_out() {
  while (inb(PS2_CMD_PORT) & 2)
    ;
}

void ps2_wait_in() {
  while (!(inb(PS2_CMD_PORT) & 1))
    ;
}

void ps2_ack() {
  while (inb(PS2_DATA_PORT) != 0xfa)
    ;
}

void ps2_clr() {
  while (inb(PS2_CMD_PORT) & 1)
    inb(PS2_DATA_PORT);
}

void ps2_port1_write(uint8_t val) {
  ps2_wait_out();
  outb(PS2_DATA_PORT, val);
}

void ps2_port2_write(uint8_t val) {
  ps2_wait_out();
  outb(PS2_CMD_PORT, 0xd4);
  ps2_wait_out();
  outb(PS2_DATA_PORT, val);
}

uint8_t ps2_read() {
  ps2_wait_in();
  return inb(PS2_DATA_PORT);
}

void mouse_handler(uint64_t rsp) {
  (void)rsp;
  switch (mouse_cycle++) {
    case 0:
      mouse_keys[0] = ps2_read();
      break;
    case 1:
      mouse_keys[1] = ps2_read();
      break;
    case 2:
      mouse_keys[2] = ps2_read();
      mouse_cycle = 0;
      break;
  }
}

void kbd_handler(uint64_t rsp) {
  (void)rsp;

  ps2_wait_in();

  uint8_t c = inb(0x60);
  char ch = 0;

  if (c == 0xe0) {
    extra_scancodes = 1;
    return;
  }

  if (extra_scancodes) {
    extra_scancodes = 0;
    switch (c) {
      case PS2_KEY_CTRL:
        ctrl_active = 1;
        return;
        ;
      case PS2_KEY_CTRL_REL:
        ctrl_active = 0;
        return;
        ;
      default:
        break;
    }
  }

  switch (c) {
    case PS2_KEY_LEFT_ALT:
      alt_active = 1;
      return;
    case PS2_KEY_LEFT_ALT_REL:
      alt_active = 0;
      return;
    case PS2_KEY_LEFT_SHIFT:
    case PS2_KEY_RIGHT_SHIFT:
      shift_active = 1;
      return;
    case PS2_KEY_LEFT_SHIFT_REL:
    case PS2_KEY_RIGHT_SHIFT_REL:
      shift_active = 0;
      return;
    case PS2_KEY_CTRL:
      ctrl_active = 1;
      return;
    case PS2_KEY_CTRL_REL:
      ctrl_active = 0;
      return;
    case PS2_KEY_CAPSLOCK:
      capslock_active = !capslock_active;
      return;
    default:
      break;
  }

  if (ctrl_active)
    switch (c) { // TODO: control sequences
      default:
        return;
    }

  if (c < PS2_KBD_MAX_CODE) {
    if (!capslock_active && !shift_active)
      ch = ps2_scancodes_norm[c];
    else if (!capslock_active && shift_active)
      ch = ps2_scandcodes_shift[c];
    else if (capslock_active && shift_active)
      ch = ps2_scandcodes_shift_capslock[c];
    else
      ch = ps2_scandcodes_capslock[c];
  } else
    return;

  pipe_write(&kbd_pipe, (uint8_t *)&ch, 1);
}

uint8_t getchar() {
  uint8_t c;
  while (pipe_read(&kbd_pipe, &c, 1) == -1)
    ;
  return c;
}

void getmouse(int8_t *bytes) {
  memcpy(bytes, mouse_keys, 3);
  memset(mouse_keys, 0, 3);
}

int init_ps2() {
  asm volatile("cli");

  pipe_init(&kbd_pipe, PS2_KBD_BUF_LEN);

  ps2_clr();

  /* Disable ports */
  ps2_wait_out();
  outb(PS2_CMD_PORT, 0xad);
  ps2_wait_out();
  outb(PS2_CMD_PORT, 0xa7);

  ps2_clr();

  uint8_t conf = 0b01000111;
  ps2_wait_out();
  outb(PS2_CMD_PORT, 0x60);
  ps2_wait_out();
  outb(PS2_DATA_PORT, conf);

  // Enable mouse
  ps2_port2_write(0xf6);
  ps2_ack();
  ps2_port2_write(0xf3);
  ps2_ack();
  ps2_port2_write(0x14);
  ps2_ack();
  ps2_port2_write(0xf4);
  ps2_ack();

  // Enable keyboard
  ps2_wait_out();
  ps2_port1_write(0xf6);
  ps2_ack();

  ps2_wait_out();
  ps2_port1_write(0xf4);
  ps2_ack();

  ioapic_redirect_irq(0, 1, 33, 1);
  ioapic_redirect_irq(0, 12, 44, 1);
  irq_install_handler(1, kbd_handler);
  irq_install_handler(12, mouse_handler);

  ps2_wait_out();
  outb(PS2_CMD_PORT, 0xae);
  ps2_wait_out();
  outb(PS2_CMD_PORT, 0xa8);

  ps2_clr();

  asm volatile("sti");

  return 0;
}
