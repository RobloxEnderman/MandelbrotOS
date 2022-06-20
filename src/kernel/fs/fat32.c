#include <dev/device.h>
#include <drivers/mbr.h>
#include <drivers/rtc.h>
#include <fb/fb.h>
#include <fs/fat32.h>
#include <fs/vfs.h>
#include <klog.h>
#include <mm/kheap.h>
#include <mm/pmm.h>
#include <mm/vmm.h>
#include <printf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

uint64_t fat_cluster_to_sector(device_t *dev, uint32_t cluster) {
  cluster -= 2;
  return (
    uint64_t)((cluster *
               (uint64_t)(((fat_fs_private_info_t *)dev->fs->private_data)
                            ->boot.cluster_size)) +
              ((fat_fs_private_info_t *)dev->fs->private_data)
                ->boot.reserved_sectors +
              ((fat_fs_private_info_t *)dev->fs->private_data)
                  ->boot.table_count *
                (uint64_t)(((fat_fs_private_info_t *)dev->fs->private_data)
                             ->boot.table_size));
}

uint32_t fat_get_next_cluster(device_t *dev, uint32_t cluster) {
  uint8_t *buf = kmalloc(512);
  uint64_t fat_sector =
    ((fat_fs_private_info_t *)dev->fs->private_data)->boot.reserved_sectors +
    ((cluster * 4) / 512);

  dev->read(dev, fat_sector, 1, buf);

  uint32_t ret = *((uint32_t *)&buf[(cluster * 4) % 512]) & 0xfffffff;

  kfree(buf);

  return ret;
}

uint32_t fat_read_cluster(device_t *dev, uint8_t *buffer, uint32_t cluster) {
  dev->read(dev, fat_cluster_to_sector(dev, cluster),
            ((fat_fs_private_info_t *)dev->fs->private_data)->boot.cluster_size,
            buffer);

  return fat_get_next_cluster(dev, cluster);
}

void fat_read_cluster_chain(device_t *dev, uint8_t *buffer, uint32_t cluster) {
  while (cluster >= 2 && cluster < 0xffffff7) {
    cluster = fat_read_cluster(dev, buffer, cluster);
    buffer +=
      ((fat_fs_private_info_t *)dev->fs->private_data)->boot.cluster_size * 512;
  }
}

size_t fat_chain_cluster_length(device_t *dev, uint32_t cluster) {
  uint8_t *buffer = kmalloc(512);
  size_t count = 0;

  while (cluster >= 2 && cluster < 0xffffff7) {
    cluster = fat_read_cluster(dev, buffer, cluster);
    count++;
  }

  kfree(buffer);

  return count;
}

void fat_change_fat_value(device_t *dev, uint32_t current_cluster,
                          uint32_t next_cluster) {
  uint8_t *buffer = kmalloc(512);
  uint64_t sector =
    ((fat_fs_private_info_t *)dev->fs->private_data)->boot.reserved_sectors +
    ((current_cluster * 4) / 512);

  dev->read(dev, sector, 1, (uint8_t *)buffer);

  buffer[(current_cluster * 4) % 512] = next_cluster;

  dev->write(dev, sector, 1, (uint8_t *)buffer);

  kfree(buffer);
}

uint32_t fat_find_free_cluster(device_t *dev) {
  uint32_t *fat_buffer = kmalloc(128 * sizeof(uint32_t));

  for (size_t i = 0;
       i < ((fat_fs_private_info_t *)dev->fs->private_data)->boot.table_size;
       i++) {
    uint64_t sector =
      ((fat_fs_private_info_t *)dev->fs->private_data)->boot.reserved_sectors +
      i;

    dev->read(dev, sector, 1, (uint8_t *)fat_buffer);

    for (uint8_t j = 0; j < 128; j++)
      if (!fat_buffer[j]) {
        kfree(fat_buffer);
        return (i * 128 + j) & 0xfffffff;
      }
  }

  kfree(fat_buffer);

  return 0xfffffff;
}

uint32_t fat_find_free_cluster_chain(device_t *dev, size_t size) {
  size_t cluster_size =
    ((fat_fs_private_info_t *)dev->fs->private_data)->boot.cluster_size * 512;
  size = (size + (cluster_size - 1)) / cluster_size;

  uint32_t start = 0;
  uint32_t previous = 0;
  uint32_t current = 0;

  while (size) {
    current = fat_find_free_cluster(dev);

    if (previous)
      fat_change_fat_value(dev, previous, current);

    fat_change_fat_value(dev, current, 0xffffff8);

    if (!start)
      start = current;

    previous = current;

    size--;
  }

  return start;
}

void fat_free_chain(device_t *dev, uint32_t cluster) {
  while (1) {
    uint32_t next = fat_get_next_cluster(dev, cluster);

    if (!next || next == 0xffffff8)
      return;

    fat_change_fat_value(dev, cluster, 0);

    cluster = next;
  }
}

uint32_t fat_get_free_dir_entry(device_t *dev, uint32_t directory) {
  fat_fs_private_info_t *partition =
    (fat_fs_private_info_t *)dev->fs->private_data;

  if (!directory)
    directory = partition->boot.root_cluster;

  size_t size =
    (fat_chain_cluster_length(dev, directory) * partition->boot.cluster_size) *
    512;

  dir_entry_t *entries = kmalloc(size);
  fat_read_cluster_chain(dev, (uint8_t *)entries, directory);

  size /= sizeof(dir_entry_t);

  for (size_t i = 0; i < size; i++) {
    if (!entries[i].filename[0] || entries[i].filename[0] == 0xe5) {
      kfree(entries);
      return i;
    }
  }

  kfree(entries);
  return 0xfffffff;
}

uint32_t fat_get_free_dir_entry_chain(device_t *dev, uint32_t directory,
                                      size_t count) {
  uint32_t old_cluster = 0;
  uint32_t start = 0;
  uint32_t new_cluster;

  if (!count)
    return -1;
  for (size_t i = 0; i < count; i++) {
    new_cluster = fat_get_free_dir_entry(dev, directory);
    if (old_cluster)
      fat_change_fat_value(dev, old_cluster, new_cluster);
    if (!start)
      start = new_cluster;
    old_cluster = new_cluster;
  }

  fat_change_fat_value(dev, new_cluster, 0xffffff8);

  return start;
}

uint32_t fat_write_cluster(device_t *dev, uint8_t *buffer, uint32_t cluster) {
  dev->write(
    dev, fat_cluster_to_sector(dev, cluster),
    ((fat_fs_private_info_t *)dev->fs->private_data)->boot.cluster_size,
    buffer);

  return fat_get_next_cluster(dev, cluster);
}

void fat_write_cluster_chain(device_t *dev, uint8_t *buffer, uint32_t cluster) {
  while (cluster >= 2 && cluster < 0xffffff7) {
    cluster = fat_write_cluster(dev, buffer, cluster);
    buffer +=
      ((fat_fs_private_info_t *)dev->fs->private_data)->boot.cluster_size * 512;
  }
}

void fat_set_dir_entry(device_t *dev, uint32_t directory, size_t index,
                       dir_entry_t entry) {
  fat_fs_private_info_t *partition =
    (fat_fs_private_info_t *)dev->fs->private_data;

  if (!directory)
    directory = partition->boot.root_cluster;

  size_t size =
    (fat_chain_cluster_length(dev, directory) * partition->boot.cluster_size) *
    512;

  if (index > size / sizeof(dir_entry_t))
    return;

  dir_entry_t *entries = kmalloc(size);
  fat_read_cluster_chain(dev, (uint8_t *)entries, directory);

  entries[index] = entry;

  fat_write_cluster_chain(dev, (uint8_t *)entries, directory);

  kfree(entries);
}

uint8_t fat_get_short_filename_checksum(uint8_t *name) {
  int i;
  uint8_t sum = 0;

  for (i = 11; i; i--)
    sum = ((sum & 1) << 7) + (sum >> 1) + *name++;
  return sum;
}

uint32_t fat_find(device_t *dev, uint32_t directory,
                  dir_entry_t *parent_cluster, uint32_t *parent_cluster_dir,
                  size_t *index, char *path) {
  uint32_t pcd;

  fat_fs_private_info_t *partition =
    (fat_fs_private_info_t *)dev->fs->private_data;

  if (directory >= 0xffffff7)
    return 0xfffffff;
  if (!directory)
    directory = partition->boot.root_cluster;
  if (parent_cluster_dir)
    *parent_cluster_dir = directory;
  if (!path)
    return directory;
  if (!strlen(path))
    return directory;
  if (!parent_cluster_dir)
    parent_cluster_dir = &pcd;

  if (path[0] == ' ' || path[0] == '/')
    return fat_find(dev, directory, parent_cluster, parent_cluster_dir, index,
                    ++path);
  else if (path[0] == '.')
    path += 2;

  /* char short_name[12] = "            "; */
  char *short_name = kmalloc(12);
  memset(short_name, ' ', 12);
  uint8_t pos = 0;

  while (*path) {
    if (pos == 11)
      break;
    if (*path == '/')
      break;

    if (*path == '.') {
      if (pos < 8)
        pos = 8;
    } else if (*path >= 'a' && *path <= 'z')
      short_name[pos++] = (*path - 'a') + 'A';
    else
      short_name[pos++] = *path;

    path++;
  }

  size_t size = fat_chain_cluster_length(dev, directory) *
                partition->boot.cluster_size * 512;
  dir_entry_t *buffer = kmalloc(size);
  fat_read_cluster_chain(dev, (uint8_t *)buffer, directory);

  size /= sizeof(dir_entry_t);

  for (size_t i = 0; i < size; i++) {
    dir_entry_t *cluster = &buffer[i];

    if (!cluster->filename[0] || cluster->filename[0] == 0xE5)
      continue;

    if (cluster->flags == 0xf) {
      long_filename_t *lfn = (void *)&buffer[i];
      size_t count = 0;

      while (lfn->flags != 0x1 && lfn->flags != 0x41) {
        count++;
        lfn = (void *)&buffer[i + count];
      }

      count++;

      lfn = (void *)&buffer[i + count - 1];

      uint8_t *long_filename = kmalloc(
        count *
        13); // Each long file name can hold 13 characters (If you convert
             // it from normal UTF16 to ASCII because nobody likes UTF16)

      memset(long_filename, 0xff, count * 13);

      for (size_t j = 0; j < count; j++) {
        for (size_t x = 0; x < 5; x++)
          long_filename[j * 13 + x] = lfn->filename_lo[x];
        for (size_t x = 0; x < 6; x++)
          long_filename[j * 13 + x + 5] = lfn->filename_mid[x];
        for (size_t x = 0; x < 2; x++)
          long_filename[j * 13 + x + 11] = lfn->filename_hi[x];

        lfn = (void *)&buffer[i + count - j - 2];
      }

      i += count;

      uint8_t *path_name = kmalloc(256);

      for (size_t i = 0; i < count * 13; i++)
        path_name[i] = 0xff;

      path -= pos;

      pos = 0;
      while (*path) {
        if (*path == '/')
          break;

        path_name[pos++] = *path;

        path++;
      }

      path_name[pos] = 0;

      i--;

      if (!strncmp((char *)path_name, (char *)long_filename, count * 13)) {
        dir_entry_t *cluster = &buffer[i + 1];

        uint32_t cluster_no = ((uint32_t)(cluster->cluster_hi) << 16) |
                              (uint32_t)(cluster->cluster_lo);

        if (*path == '/' && cluster->directory) {
          kfree(path_name);
          kfree(long_filename);
          kfree(buffer);

          if (*(path + 2) != '.' && *(path + 3) != '.')
            cluster_no = fat_find(dev, cluster_no, parent_cluster,
                                  parent_cluster_dir, index, path + 1);
          else
            cluster_no = fat_find(dev, *parent_cluster_dir, parent_cluster,
                                  parent_cluster_dir, index, path + 4);
        } else {
          kfree(path_name);
          kfree(long_filename);
          kfree(short_name);
          kfree(buffer);

          if (parent_cluster)
            *parent_cluster = *cluster;
          if (index)
            *index = i + 1;

          *parent_cluster_dir = directory;
        }

        return cluster_no;
      }

      kfree(path_name);
      kfree(long_filename);
      kfree(short_name);

    } else {
      if (!strncmp(short_name, (char *)cluster->filename, 11)) {
        uint32_t cluster_no = ((uint32_t)(cluster->cluster_hi) << 16) |
                              (uint32_t)(cluster->cluster_lo);

        kfree(buffer);
        kfree(short_name);

        if (*path == '/' && cluster->directory) {
          if (*(path + 2) != '.' && *(path + 3) != '.')
            cluster_no = fat_find(dev, cluster_no, parent_cluster,
                                  parent_cluster_dir, index, path + 1);
          else
            cluster_no = fat_find(dev, *parent_cluster_dir, parent_cluster,
                                  parent_cluster_dir, index, path + 4);
        } else {
          if (parent_cluster)
            *parent_cluster = *cluster;
          if (index)
            *index = i;

          *parent_cluster_dir = directory;
        }

        return cluster_no;
      }
    }
  }

  kfree(buffer);
  kfree(short_name);

  return 0xfffffff;
}

// This is only the functions I need to link the FAT driver to the VFS
uint64_t fat_ioctl(fs_file_t *file, uint64_t cmd, void *arg) {
  // TODO: Do I need IOCTL for fat?
  (void)file;
  (void)cmd;
  (void)arg;
  return 0;
}

int fat_chmod(fs_file_t *file, int mode) {
  // Fat doesn't support this sadly
  file->mode = mode;
  return 0;
}

int fat_chown(fs_file_t *file, int uid, int gid) {
  // No perms for fat. Sad
  file->uid = uid;
  file->gid = gid;
  return 0;
}

fs_file_t *fat_mknod(fs_t *fs, char *name, int mode, int uid, int gid,
                     device_t *dev) {
  (void)fs;
  (void)name;
  (void)mode;
  (void)dev;
  (void)uid;
  (void)gid;
  return NULL;
}

void *fat_mmap(fs_file_t *file, pagemap_t *pg, syscall_file_t *sfile,
               void *addr, size_t size, size_t offset, int prot, int flags) {
  (void)file;
  (void)pg;
  (void)addr;
  (void)size;
  (void)offset;
  (void)flags;
  (void)sfile;
  (void)prot;
  return NULL;
}

fs_file_t *fat_mkfifo(fs_t *fs, char *path, int mode, int uid, int gid) {
  (void)fs;
  (void)path;
  (void)mode;
  (void)uid;
  (void)gid;
  return NULL;
}

int fat_truncate(fs_file_t *file, size_t size) {
  size_t index = ((fat_file_private_info_t *)file->private_data)->index;
  uint32_t dir =
    ((fat_file_private_info_t *)file->private_data)->parent_cluster;
  uint32_t cluster = ((fat_file_private_info_t *)file->private_data)->cluster;
  dir_entry_t entry = ((fat_file_private_info_t *)file->private_data)->dir;

  if ((entry.size /
       ((fat_fs_private_info_t *)file->fs->private_data)->boot.cluster_size) >
      (size /
       ((fat_fs_private_info_t *)file->fs->private_data)->boot.cluster_size)) {
    while (1) {
      uint32_t next = fat_get_next_cluster(file->fs->dev, cluster);

      if (!next || next == 0xffffff8) {
        fat_change_fat_value(file->fs->dev, cluster, 0xffffff8);
        break;
      }

      cluster = next;
    }
  } else if ((entry.size / ((fat_fs_private_info_t *)file->fs->private_data)
                             ->boot.cluster_size) <
             (size / ((fat_fs_private_info_t *)file->fs->private_data)
                       ->boot.cluster_size)) {
    uint32_t new_writing_cluster =
      fat_find_free_cluster(file->fs->private_data);
    while (1) {
      uint32_t next = fat_get_next_cluster(file->fs->dev, cluster);

      if (!next || next == 0xffffff8) {
        fat_change_fat_value(file->fs->dev, cluster, new_writing_cluster);
        fat_change_fat_value(file->fs->dev, new_writing_cluster, 0xffffff8);
        break;
      }

      cluster = next;
    }
  }

  entry.size = size;
  fat_set_dir_entry(file->fs->dev, dir, index, entry);

  return 0;
}

ssize_t fat_read(fs_file_t *file, uint8_t *buf, size_t offset, size_t count) {
  datetime_t time = rtc_get_datetime();
  time.year += 1900;

  size_t index = ((fat_file_private_info_t *)file->private_data)->index;
  uint32_t dir =
    ((fat_file_private_info_t *)file->private_data)->parent_cluster;
  dir_entry_t entry = ((fat_file_private_info_t *)file->private_data)->dir;

  entry.accessed_day = time.day;
  entry.accessed_month = time.month;
  entry.accessed_year = time.year - 1980;

  fat_set_dir_entry(file->fs->dev, dir, index, entry);

  if (entry.directory)
    return 0;
  if (entry.size < offset + count)
    count = entry.size - offset;
  if (!count)
    return 0;

  uint8_t *file_buffer = kmalloc(entry.size);
  fat_read_cluster_chain(
    file->fs->dev, file_buffer,
    ((uint32_t)(entry.cluster_hi << 16) | (uint32_t)(entry.cluster_lo)));

  memcpy(buf, file_buffer + offset, count);

  kfree(file_buffer);

  return count;
}

ssize_t fat_write(fs_file_t *file, uint8_t *buf, size_t offset, size_t count) {
  datetime_t time = rtc_get_datetime();

  size_t index = ((fat_file_private_info_t *)file->private_data)->index;
  uint32_t dir =
    ((fat_file_private_info_t *)file->private_data)->parent_cluster;
  uint32_t writing_cluster =
    ((fat_file_private_info_t *)file->private_data)->cluster;
  dir_entry_t entry = ((fat_file_private_info_t *)file->private_data)->dir;

  entry.accessed_day = time.day;
  entry.accessed_month = time.month;
  entry.accessed_year = time.year - 1980;

  if (!count)
    return 0;
  if (entry.directory)
    return 0;

  while (
    count + offset >
    fat_chain_cluster_length(file->fs->dev, writing_cluster) *
      ((fat_fs_private_info_t *)file->fs->private_data)->boot.cluster_size *
      512) {
    uint32_t last_entry_in_chain =
      ((uint32_t)(entry.cluster_hi << 16) | (uint32_t)(entry.cluster_lo));

    for (size_t i = 0;
         i < fat_chain_cluster_length(file->fs->dev, writing_cluster) - 1; i++)
      last_entry_in_chain =
        fat_get_next_cluster(file->fs->dev, last_entry_in_chain);

    uint32_t free_entry = fat_find_free_cluster(file->fs->dev);
    fat_change_fat_value(file->fs->dev, last_entry_in_chain, free_entry);
    fat_change_fat_value(file->fs->dev, free_entry, 0xffffff8);
  }

  uint8_t *file_buffer = kmalloc(
    fat_chain_cluster_length(file->fs->dev, writing_cluster) *
    ((fat_fs_private_info_t *)file->fs->private_data)->boot.cluster_size * 512);

  fat_read_cluster_chain(file->fs->dev, file_buffer, writing_cluster);

  memcpy(file_buffer + offset, buf, count);

  fat_write_cluster_chain(file->fs->dev, file_buffer, writing_cluster);

  entry.modified_day = time.day;
  entry.modified_month = time.month;
  entry.modified_year = time.year - 1980;
  entry.modified_hour = time.hours;
  entry.modified_minute = time.minutes;
  entry.modified_second = time.seconds / 2;

  if (offset + count > entry.size) {
    file->length = offset + count;
    entry.size = offset + count;
  }

  fat_set_dir_entry(file->fs->dev, dir, index, entry);

  kfree(file_buffer);

  return count;
}

int fat_readdir(fs_file_t *file, dirent_t *dirent, size_t pos) {
  datetime_t time = rtc_get_datetime();
  time.year += 1900;

  uint32_t cluster =
    ((fat_file_private_info_t *)file->private_data)->parent_cluster;
  uint32_t current_dir =
    ((fat_file_private_info_t *)file->private_data)->cluster;

  size_t size = fat_chain_cluster_length(file->fs->dev, cluster) * 512;
  dir_entry_t *entries = kmalloc(size);

  size /= sizeof(dir_entry_t);

  fat_read_cluster_chain(file->fs->dev, (uint8_t *)entries, cluster);

  if (entries[pos].flags == 0xf) {
    long_filename_t *lfn = (void *)&entries[pos];
    size_t count = 0;

    while (lfn->flags != 0x1 && lfn->flags != 0x41) {
      count++;
      lfn = (void *)&entries[pos + count];
    }

    count++;

    lfn = (void *)&entries[pos + count - 1];

    uint8_t *long_filename = kmalloc(
      count * 13); // Each long file name can hold 13 characters (If you convert
                   // it from normal UTF16 to ASCII because nobody likes UTF16);

    for (size_t j = 0; j < count; j++) {
      for (size_t x = 0; x < 5; x++)
        long_filename[j * 13 + x] = lfn->filename_lo[x];
      for (size_t x = 0; x < 6; x++)
        long_filename[j * 13 + x + 5] = lfn->filename_mid[x];
      for (size_t x = 0; x < 2; x++)
        long_filename[j * 13 + x + 11] = lfn->filename_hi[x];

      lfn = (void *)&entries[pos + count - j - 2];
    }

    strcat(dirent->name, (char *)long_filename);

    kfree(long_filename);

    return 0;
  }

  entries[pos].accessed_day = time.day;
  entries[pos].accessed_month = time.month;
  entries[pos].accessed_year = time.year - 1980;

  fat_set_dir_entry(
    file->fs->dev, current_dir,
    pos %
      (((fat_fs_private_info_t *)file->fs->private_data)->boot.cluster_size *
       512 / sizeof(dir_entry_t)),
    entries[pos]);

  strcat(dirent->name, (char *)entries[pos].filename);
  dirent->name[11] = 0;

  return 0;
}

int fat_close(fs_file_t *file) {
  kfree(file->private_data);
  kfree(file);
  return 0;
}

int fat_delete(fs_file_t *file) {
  uint32_t cluster =
    ((fat_file_private_info_t *)file->private_data)->parent_cluster;
  dir_entry_t entry = ((fat_file_private_info_t *)file->private_data)->dir;
  uint32_t dir = ((fat_file_private_info_t *)file->private_data)->cluster;
  size_t index = ((fat_file_private_info_t *)file->private_data)->index;

  if (entry.directory) {
    return 1;
  } else {
    fat_free_chain(file->fs->dev, cluster);
    entry.filename[0] = 0xe5;
    fat_set_dir_entry(file->fs->dev, dir, index, entry);
  }

  return fat_close(file);
}

int fat_rmdir(fs_file_t *file) {
  uint32_t cluster =
    ((fat_file_private_info_t *)file->private_data)->parent_cluster;
  dir_entry_t entry = ((fat_file_private_info_t *)file->private_data)->dir;
  uint32_t dir = ((fat_file_private_info_t *)file->private_data)->cluster;
  size_t index = ((fat_file_private_info_t *)file->private_data)->index;

  if (!entry.directory) {
    return 1;
  } else {
    // TODO: Make this recursive as this can trash a directory and not do it's
    // contents.
    fat_free_chain(file->fs->dev, cluster);
    entry.filename[0] = 0xe5;
    fat_set_dir_entry(file->fs->dev, dir, index, entry);
  }

  return fat_close(file);
}

file_ops_t fat_file_ops = (file_ops_t){
  .read = fat_read,
  .write = fat_write,
  .rmdir = fat_rmdir,
  .delete = fat_delete,
  .truncate = fat_truncate,
  .close = fat_close,
  .readdir = fat_readdir,
  .ioctl = fat_ioctl,
  .chmod = fat_chmod,
  .chown = fat_chown,
  .mmap = fat_mmap,
};

fs_file_t *fat_open(fs_t *fs, char *path) {
  fat_file_private_info_t *priv = kmalloc(sizeof(fat_file_private_info_t));
  if ((priv->cluster = fat_find(fs->dev, 0, &priv->dir, &priv->parent_cluster,
                                &priv->index, path)) == 0xfffffff)
    return NULL;

  fs_file_t *file = kmalloc(sizeof(fs_file_t));
  *file = (fs_file_t){
    .uid = 0,
    .gid = 0,
    .file_ops = &fat_file_ops,
    .fs = fs,
    .path = path,
    .length = priv->dir.size,
    .inode = priv->cluster,
    .private_data = (void *)priv,
    .mode = S_IRUSR | S_IRGRP | S_IROTH | S_IXUSR | S_IXGRP | S_IXOTH |
            ((priv->dir.directory) ? S_IFDIR : S_IFREG) |
            ((!priv->dir.read_only) ? S_IWUSR | S_IWGRP | S_IWOTH : 0),

    .last_access_time =
      rtc_mktime((datetime_t){.day = priv->dir.accessed_day,
                              .month = priv->dir.accessed_month,
                              .year = priv->dir.accessed_year + 1980}),
    .last_modification_time =
      rtc_mktime((datetime_t){.day = priv->dir.modified_day,
                              .month = priv->dir.modified_month,
                              .year = priv->dir.modified_year + 1980,
                              .seconds = priv->dir.modified_second * 2,
                              .minutes = priv->dir.modified_minute,
                              .hours = priv->dir.modified_hour}),
    .last_status_change_time =
      rtc_mktime((datetime_t){.day = priv->dir.modified_day,
                              .month = priv->dir.modified_month,
                              .year = priv->dir.modified_year + 1980,
                              .seconds = priv->dir.modified_second * 2,
                              .minutes = priv->dir.modified_minute,
                              .hours = priv->dir.modified_hour}),

    .creation_time = rtc_mktime((datetime_t){
      .day = priv->dir.created_day,
      .month = priv->dir.created_month,
      .year = priv->dir.created_year + 1980,
      .seconds = priv->dir.created_second * 2 + (priv->dir.created_ticks % 2),
      .minutes = priv->dir.created_minute,
      .hours = priv->dir.created_hour}),
    .offset = 0,
    .ref_count = 1,
  };

  return file;
}

fs_file_t *fat_create(fs_t *fs, char *path, int mode, int uid, int gid) {
  (void)uid;
  (void)gid;
  (void)mode;

  char *orig_path = path;

  datetime_t time = rtc_get_datetime();
  time.year += 1900;

  uint32_t parent_cluster;

  if (fat_find(fs->dev, 0, NULL, &parent_cluster, NULL, path) != 0xfffffff)
    return fat_open(fs, path);

  path = strrchr(path, '/');
  if (!path)
    return NULL;

  path++;

  int is_long_filename = 0;
  size_t count = 0;
  size_t name_length = 0;
  while (1) {
    if (path[count] == 0)
      break;
    if (path[count] == '.') {
      count++;
      continue;
    }
    if (name_length > 10) {
      is_long_filename = 1;
      break;
    }

    name_length++;
    count++;
  }

  if (is_long_filename) {
    char short_path[11] = "           ";
    uint8_t pos = 0;

    while (*path) {
      if (pos == 11)
        break;
      if (pos > 6) {
        short_path[6] = '~';
        short_path[7] = '0';
      }
      if (*path == '.') {
        if (pos < 8)
          pos = 8;
      } else if (*path >= 'a' && *path <= 'z')
        short_path[pos++] = (*path - 'a') + 'A';
      else
        short_path[pos++] = *path;

      path++;
    }

    char *tmp_short_name = kmalloc(13);
    memcpy(tmp_short_name + 1, short_path, 11);
    tmp_short_name[0] = '/';

    while (fat_find(fs->dev, parent_cluster, NULL, NULL, NULL,
                    tmp_short_name) != 0xfffffff)
      tmp_short_name[7]++;

    short_path[6] = tmp_short_name[7];

    path -= pos;

    size_t len = strlen(path) / 13 + 1;
    size_t index = fat_get_free_dir_entry_chain(fs->dev, parent_cluster, len);
    uint8_t placement = 1;
    long_filename_t lfn = {0};
    int done = 0;

    for (size_t i = 0; i < len; i++) {
      memset(&lfn, 0xff, 32);

      for (size_t j = 0; j < 5; j++) {
        if (!done) {
          if (*path == 0) {
            done = 1;
            lfn.filename_lo[j] = 0;
            continue;
          }
          lfn.filename_lo[j] = *path;
          path++;
        } else
          lfn.filename_lo[j] = 0xffff;
      }
      for (size_t j = 0; j < 6; j++) {
        if (!done) {
          if (*path == 0) {
            done = 1;
            lfn.filename_mid[j] = 0;
            continue;
          }
          lfn.filename_mid[j] = *path;
          path++;
        } else
          lfn.filename_mid[j] = 0xffff;
      }
      for (size_t j = 0; j < 2; j++) {
        if (!done) {
          if (*path == 0) {
            done = 1;
            lfn.filename_hi[j] = 0;
            continue;
          }
          lfn.filename_hi[j] = *path;
          path++;
        } else
          lfn.filename_hi[j] = 0xffff;
      }

      lfn.attribute = 0xf;
      lfn.flags = placement;
      lfn.zero = 0;
      lfn.long_entry = 0;
      lfn.checksum_of_short_name = 0;

      lfn.checksum_of_short_name =
        fat_get_short_filename_checksum((uint8_t *)short_path);

      fat_set_dir_entry(fs->dev, parent_cluster, index + len - 1 - i,
                        *(dir_entry_t *)(void *)&lfn);

      if (placement == len - 1)
        placement = ((placement + 1) | 0x40);
      else
        placement++;
    }

    dir_entry_t dir = {0};

    uint32_t new_writing_cluster = fat_find_free_cluster_chain(fs->dev, 1);

    dir.cluster_lo = new_writing_cluster;
    dir.cluster_hi = new_writing_cluster >> 16;

    dir.accessed_day = time.day;
    dir.accessed_month = time.month;
    dir.accessed_year = time.year - 1980;

    dir.created_day = time.day;
    dir.created_month = time.month;
    dir.created_year = time.year - 1980;
    dir.created_hour = time.hours;
    dir.created_minute = time.minutes;
    dir.created_second = time.seconds / 2;
    dir.created_ticks = time.seconds % 2;

    dir.modified_day = time.day;
    dir.modified_month = time.month;
    dir.modified_year = time.year - 1980;
    dir.modified_hour = time.hours;
    dir.modified_minute = time.minutes;
    dir.modified_second = time.seconds / 2;

    memcpy(dir.filename, short_path, 11);
    fat_set_dir_entry(fs->dev, parent_cluster, index + len, dir);

    kfree(tmp_short_name);
  } else {
    char *short_path = kmalloc(11);
    memset(short_path, ' ', 11);
    uint8_t pos = 0;

    while (*path) {
      if (pos == 11)
        break;

      if (*path == '.') {
        if (pos < 8)
          pos = 8;
      } else if (*path >= 'a' && *path <= 'z')
        short_path[pos++] = (*path - 'a') + 'A';
      else
        short_path[pos++] = *path;

      path++;
    }

    size_t index = fat_get_free_dir_entry_chain(fs->dev, parent_cluster, 1);

    dir_entry_t dir = {0};

    uint32_t new_writing_cluster = fat_find_free_cluster_chain(fs->dev, 1);

    dir.cluster_lo = new_writing_cluster;
    dir.cluster_hi = new_writing_cluster >> 16;

    dir.accessed_day = time.day;
    dir.accessed_month = time.month;
    dir.accessed_year = time.year - 1980;

    dir.created_day = time.day;
    dir.created_month = time.month;
    dir.created_year = time.year - 1980;
    dir.created_hour = time.hours;
    dir.created_minute = time.minutes;
    dir.created_second = time.seconds / 2;
    dir.created_ticks = time.seconds % 2;

    dir.modified_day = time.day;
    dir.modified_month = time.month;
    dir.modified_year = time.year - 1980;
    dir.modified_hour = time.hours;
    dir.modified_minute = time.minutes;
    dir.modified_second = time.seconds / 2;

    dir.size = 0;

    memcpy(dir.filename, (uint8_t *)short_path, 11);
    fat_set_dir_entry(fs->dev, parent_cluster, index, dir);

    kfree(short_path);
  }

  return fat_open(fs, orig_path);
}

fs_file_t *fat_mkdir(fs_t *fs, char *path, int mode, int uid, int gid) {
  (void)uid;
  (void)gid;
  (void)mode;

  char *unmodified_path = path;

  datetime_t time = rtc_get_datetime();
  time.year += 1900;

  uint32_t parent_cluster;

  if (fat_find(fs->dev, 0, NULL, &parent_cluster, NULL, path) != 0xfffffff)
    return fat_open(fs, path);

  path = strrchr(path, '/');
  if (!path)
    return NULL;

  path++;

  int is_long_filename = 0;
  size_t count = 0;
  size_t name_length = 0;
  while (1) {
    if (path[count] == 0)
      break;
    if (path[count] == '.') {
      count++;
      continue;
    }
    if (name_length > 10) {
      is_long_filename = 1;
      break;
    }

    name_length++;
    count++;
  }

  if (is_long_filename) {
    char *short_path = kmalloc(11);
    memset(short_path, ' ', 11);
    uint8_t pos = 0;

    while (*path) {
      if (pos == 11)
        break;
      if (pos > 6) {
        short_path[6] = '~';
        short_path[7] = '0';
      }
      if (*path >= 'a' && *path <= 'z')
        short_path[pos++] = (*path - 'a') + 'A';
      else
        short_path[pos++] = *path;

      path++;
    }

    char *tmp_short_name = kmalloc(13);
    memcpy(tmp_short_name + 1, short_path, 11);
    tmp_short_name[0] = '/';

    while (fat_find(fs->dev, parent_cluster, NULL, NULL, NULL,
                    tmp_short_name) != 0xfffffff)
      tmp_short_name[7]++;

    short_path[6] = tmp_short_name[7];

    path -= pos;

    size_t len = strlen(path) / 13 + 1;
    size_t index = fat_get_free_dir_entry_chain(fs->dev, parent_cluster, len);
    uint8_t placement = 1;
    long_filename_t lfn = {0};
    int done = 0;

    for (size_t i = 0; i < len; i++) {
      memset(&lfn, 0xff, 32);

      for (size_t j = 0; j < 5; j++) {
        if (!done) {
          if (*path == 0) {
            done = 1;
            lfn.filename_lo[j] = 0;
            continue;
          }
          lfn.filename_lo[j] = *path;
          path++;
        } else
          lfn.filename_lo[j] = 0xffff;
      }
      for (size_t j = 0; j < 6; j++) {
        if (!done) {
          if (*path == 0) {
            done = 1;
            lfn.filename_mid[j] = 0;
            continue;
          }
          lfn.filename_mid[j] = *path;
          path++;
        } else
          lfn.filename_mid[j] = 0xffff;
      }
      for (size_t j = 0; j < 2; j++) {
        if (!done) {
          if (*path == 0) {
            done = 1;
            lfn.filename_hi[j] = 0;
            continue;
          }
          lfn.filename_hi[j] = *path;
          path++;
        } else
          lfn.filename_hi[j] = 0xffff;
      }

      lfn.attribute = 0xf;
      lfn.flags = placement;
      lfn.zero = 0;
      lfn.long_entry = 0;
      lfn.checksum_of_short_name = 0;

      lfn.checksum_of_short_name =
        fat_get_short_filename_checksum((uint8_t *)short_path);

      fat_set_dir_entry(fs->dev, parent_cluster, index + len - 1 - i,
                        *(dir_entry_t *)(void *)&lfn);

      if (placement == len - 1)
        placement = ((placement + 1) | 0x40);
      else
        placement++;
    }

    dir_entry_t dir = {0};

    uint32_t new_writing_cluster = fat_find_free_cluster_chain(fs->dev, 1);

    dir.accessed_day = time.day;
    dir.accessed_month = time.month;
    dir.accessed_year = time.year - 1980;

    dir.created_day = time.day;
    dir.created_month = time.month;
    dir.created_year = time.year - 1980;
    dir.created_hour = time.hours;
    dir.created_minute = time.minutes;
    dir.created_second = time.seconds / 2;
    dir.created_ticks = (time.seconds % 2) * 100;

    dir.modified_day = time.day;
    dir.modified_month = time.month;
    dir.modified_year = time.year - 1980;
    dir.modified_hour = time.hours;
    dir.modified_minute = time.minutes;
    dir.modified_second = time.seconds / 2;

    dir.cluster_lo = new_writing_cluster;
    dir.cluster_hi = new_writing_cluster >> 16;
    dir.directory = 1;

    memcpy(dir.filename, short_path, 11);
    fat_set_dir_entry(fs->dev, parent_cluster, index + len, dir);

    dir_entry_t dot_dir = (dir_entry_t){
      .filename = ".          ",
      .cluster_lo = (uint16_t)new_writing_cluster,
      .cluster_hi = (uint16_t)(new_writing_cluster >> 16),
      .directory = 1,
    };

    fat_set_dir_entry(fs->dev, new_writing_cluster, 0, dot_dir);

    dot_dir = (dir_entry_t){
      .filename = "..         ",
      .cluster_lo = (uint16_t)new_writing_cluster,
      .cluster_hi = (uint16_t)(new_writing_cluster >> 16),
      .directory = 1,
    };

    fat_set_dir_entry(fs->dev, new_writing_cluster, 1, dot_dir);

    kfree(short_path);
    kfree(tmp_short_name);
  } else {
    char *short_path = kmalloc(11);
    memset(short_path, ' ', 11);
    uint8_t pos = 0;

    while (*path) {
      if (pos == 11)
        break;

      if (*path >= 'a' && *path <= 'z')
        short_path[pos++] = (*path - 'a') + 'A';
      else
        short_path[pos++] = *path;

      path++;
    }

    size_t index = fat_get_free_dir_entry_chain(fs->dev, parent_cluster, 1);

    dir_entry_t dir = {0};

    uint32_t new_writing_cluster = fat_find_free_cluster_chain(fs->dev, 1);

    dir.accessed_day = time.day;
    dir.accessed_month = time.month;
    dir.accessed_year = time.year - 1980;

    dir.created_day = time.day;
    dir.created_month = time.month;
    dir.created_year = time.year - 1980;
    dir.created_hour = time.hours;
    dir.created_minute = time.minutes;
    dir.created_second = time.seconds / 2;
    dir.created_ticks = (time.seconds % 2) * 100;

    dir.modified_day = time.day;
    dir.modified_month = time.month;
    dir.modified_year = time.year - 1980;
    dir.modified_hour = time.hours;
    dir.modified_minute = time.minutes;
    dir.modified_second = time.seconds / 2;

    dir.cluster_lo = new_writing_cluster;
    dir.cluster_hi = new_writing_cluster >> 16;
    dir.directory = 1;

    memcpy(dir.filename, (uint8_t *)short_path, 11);
    fat_set_dir_entry(fs->dev, parent_cluster, index, dir);

    memcpy(dir.filename, ".          ", 11);
    fat_set_dir_entry(
      fs->dev, new_writing_cluster,
      fat_get_free_dir_entry_chain(fs->dev, new_writing_cluster, 1), dir);

    memcpy(dir.filename, "..         ", 11);
    fat_set_dir_entry(
      fs->dev, new_writing_cluster,
      fat_get_free_dir_entry_chain(fs->dev, new_writing_cluster, 1), dir);

    kfree(short_path);
  }

  return fat_open(fs, unmodified_path);
}

fs_ops_t fat_fs_ops;

fs_t *fat_mount(device_t *dev) {
  bpb_t bios_block;
  dev->read(dev, 0, 1, (uint8_t *)&bios_block);

  if (bios_block.signature != 0x28 && bios_block.signature != 0x29)
    return NULL;

  fs_t *fs = kmalloc(sizeof(fs_t));
  fs->dev = dev;
  fs->ops = &fat_fs_ops;
  fs->private_data = (void *)kmalloc(sizeof(fat_fs_private_info_t));

  *((fat_fs_private_info_t *)fs->private_data) = (fat_fs_private_info_t){
    .boot = bios_block,
  };

  return fs;
}

fs_ops_t fat_fs_ops = (fs_ops_t){
  .create = fat_create,
  .mkdir = fat_mkdir,
  .mount = fat_mount,
  .open = fat_open,
  .mknod = fat_mknod,
  .mkfifo = fat_mkfifo,
};

int init_fat() {
  fat_fs_ops.fs_name = strdup("FAT32");
  vfs_register_fs(&fat_fs_ops);
  return 0;
}
