/* 
 * v9fs
 * 
 * Adjust native 9P FS in Linux for OSv
 *
 * v9fs_vnops.cc
 *     v9fs_vnops [V9FS Vnode Interface]
 *         v9fs_open      - 打开文件
 *         v9fs_close     - 关闭文件
 *         v9fs_read      - 读取文件
 *         v9fs_write     - 写入文件
 *         v9fs_seek      - 更新位置
 *         v9fs_ioctl     - 发送命令
 *         v9fs_fsync     - 同步缓存
 *         v9fs_readdir   - 读取目录
 *         v9fs_lookup    - 寻找文件
 *         v9fs_create    - 创建文件
 *         v9fs_rename    - 重命名文件
 *         v9fs_remove    - 删除文件
 *         v9fs_mkdir     - 创建目录
 *         v9fs_rmdir     - 删除目录
 *         v9fs_getattr   - 读取属性
 *         v9fs_setattr   - 设置属性
 *         v9fs_inactive  - 回收Vnode
 *         v9fs_truncate  - 截断文件
 *         v9fs_link      - 建立硬连接
 *         v9fs_arc       - [Unknown]
 *         v9fs_fallocate - 分配存储
 *         v9fs_readlink  - 读取连接
 *         v9fs_symlink   - 建立软连接
 *
 */

#include "v9fs.hh"
#include <osv/debug.h>
#include <sys/param.h>

struct p9_rdir {
    int head;
    int tail;
    char buf[];
};

static const char *get_node_name(struct vnode *node)
{
    if (LIST_EMPTY(&node->v_names) == 1) {
        return nullptr;
    }

    return LIST_FIRST(&node->v_names)->d_path;
}

static inline std::string mkpath(struct vnode *node, const char *name)
{
    std::string path(get_node_name(node));
    return path + "/" + name;
}

/* 初始化整个文件系统,而非单个挂载实例
 */
int v9fs_init(void)
{
    // v9fs_cache_register
    // v9fs_sysfs_init
    return 0;
}

/* 释放整个文件系统,而非单个挂载实例
 */
void v9fs_fini(void)
{
    // v9fs_sysfs_cleanup
    // v9fs_cache_unregister
}

/* Open or close a file
 * 填充fp->f_dentry->d_vode->v_data,即fid
 * [Debug] Cookie是什么鬼, mode, perm怎么转换
 */
static int v9fs_open(struct file *fp)
{
    int err;
    struct vnode *vp = file_dentry(fp)->d_vnode;
    struct v9fs_inode *inode = (struct v9fs_inode *) vp->v_data;
    int omode;

    debugf("file: %p\n", fp);

    if (inode->handle_fid)
    {
        return 0;
    }

    if (inode->fid->clnt->p9_is_proto_dotl())
    {
        omode = v9fs_flags2omode_dotl(fp->f_flags);
    }
    else
    {
        omode = v9fs_flags2omode(fp->f_flags, inode->fid->clnt->p9_is_proto_dotu());
    }
    inode->handle_fid = p9_client::p9_client_walk(inode->fid, 0, nullptr, 0);
    if (!(inode->handle_fid))
    {
        return -1;
    }
    err = p9_client::p9_client_open(inode->handle_fid, omode);
    if (err < 0)
    {
        debugf("V9FS: p9_client_open failed %d\n", err);
    }
    
    // if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE)
    //     v9fs_cache_inode_set_cookie(inode, file);

    return err;
}

/* Close a file
 * 关闭文件,关闭handle_fid
 * [OK]
 */
static int v9fs_close(struct vnode *vp, struct file *fp)
{
    struct v9fs_inode *inode = (struct v9fs_inode *) vp->v_data;
    struct v9fs_dirent *entry;
    struct v9fs_dirent *next;

    p9_client::p9_client_clunk(inode->handle_fid);
    inode->handle_fid = nullptr;
    if (inode->entries)
    {
        /* 如果是目录,释放子目录项
         */
        entry = inode->entries;
        while (entry)
        {
            next = entry->next;
            free(entry);
            entry = next;
        }
        inode->entries = nullptr;
        inode->current = nullptr;
    }
    
    return 0;
}

/* Read a file without cache
 * 不使用cache读取文件
 * [OK]
 */
static int v9fs_read_without_cache(struct vnode *vp, struct file *fp, struct uio *uio, int ioflag)
{
    struct p9_fid *fid = ((struct v9fs_inode *) vp->v_data)->handle_fid;
    int ret, err = 0;

    if (vp->v_type == VDIR) {
        return EISDIR;
    }
    if (vp->v_type != VREG) {
        return EINVAL;
    }
    if (uio->uio_offset < 0) {
        return EINVAL;
    }
    if (uio->uio_resid == 0) {
        return 0;
    }

    if (uio->uio_offset >= (off_t)vp->v_size) {
        return 0;
    }

    size_t len;
    if (vp->v_size - uio->uio_offset < uio->uio_resid)
    {
        len = vp->v_size - uio->uio_offset;
    }
    else
    {
        len = uio->uio_resid;
    }

    ret = p9_client::p9_client_read(fid, uio, len, &err);
    if (!ret)
    {
        debugf("V9FS: p9_client_read_uio failed %d\n", err);
    }

    return err;
}

/* Read a file with cache
 * 使用cache读取文件
 * [Debug] 暂未实现cache (cache似乎还有多种模式或级别)
 */
static int v9fs_read_with_cache(struct vnode *vp, struct file *fp, struct uio *uio, int ioflag)
{
    return v9fs_read_without_cache(vp, fp, uio, ioflag);
}

/* Write a file
 * 写文件
 * [OK]
 */
static int v9fs_write(struct vnode *vp, struct uio *uio, int ioflag)
{
    struct p9_fid *fid = ((struct v9fs_inode *) vp->v_data)->handle_fid;
    int ret, err = 0;
    size_t new_size;

    if (vp->v_type == VDIR) {
        return EISDIR;
    }
    if (vp->v_type != VREG) {
        return EINVAL;
    }
    if (uio->uio_offset < 0) {
        return EINVAL;
    }
    if (uio->uio_resid == 0) {
        return 0;
    }

    new_size = vp->v_size;
    if (ioflag & IO_APPEND) {

        uio->uio_offset = vp->v_size;
        new_size = vp->v_size + uio->uio_resid;
    } else if ((uio->uio_offset + uio->uio_resid) > vp->v_size) {
        new_size = uio->uio_offset + uio->uio_resid;
    }

    ret = p9_client::p9_client_write(fid, uio, uio->uio_resid, &err);
    if (!ret)
    {
        debugf("V9FS: p9_client_read_uio failed %d\n", err);
        return err;
    }

    vp->v_size = new_size;

    return 0;
}

/* Seek a file
 * 移动文件位置
 * [Debug] 暂不支持: 是否需要支持此操作,或者是否有可能支持此操作
 */
static int v9fs_seek(struct vnode *vp, struct file *fp, off_t ooff, off_t noffp)
{
    debugf("V9FS: Unsupported file operation: seek\n");
    return 0;
}

/* Control a device file
 * 控制设备文件
 * [Debug] 暂不支持: 是否需要支持此操作,或者是否有可能支持此操作
 */
static int v9fs_ioctl(struct vnode *vp, struct file *fp, u_long com, void *data)
{
    debugf("V9FS: Unsupported file operation: ioctl\n");
    return 0;
}

/* Sync a file
 * 同步文件
 * [Debug] 仅有2000.L支持同步操作,2000, 2000.u是否可以支持
 */
static int v9fs_fsync(struct vnode *vp, struct file *fp)
{
    struct p9_fid *fid = ((struct v9fs_inode *) vp->v_data)->handle_fid;

    if (fid->clnt->p9_is_proto_dotl())
    {
        /* 2000.L使用p9_client_fsync同步root
         */
        return p9_client::p9_client_fsync(fid, 0);
    }
    else
    {
        /* 2000, 2000.u似乎无文件/文件系统同步原语
         * 使用p9_client_write, p9_client_wstat?
         */
        debugf("V9FS: Unsupported file operation: fsync\n");
        /* Write and wait range
         */

        struct p9_wstat st;
        v9fs_blank_wstat(&st);
        return p9_client::p9_client_setattr(fid, &st);
    }

}

static inline int dt_type(struct p9_wstat *mistat)
{
    unsigned long perm = mistat->mode;
    int rettype = DT_REG;

    if (perm & P9_DMDIR)
        rettype = DT_DIR;
    if (perm & P9_DMSYMLINK)
        rettype = DT_LNK;

    return rettype;
}

/* Load Children Entries of a directory
 * 2000, 2000.u加载目录的子目录项
 * [OK] 源于Linux内核
 */
static int load_dir_entries(struct v9fs_inode *inode)
{
    loff_t pos = 0;
    int err;
    int buflen;
    struct p9_wstat st;
    int reclen = 0;
    struct uio uio;
    struct iovec iov;
    int n;
    struct p9_fid *fid = inode->fid;
    struct p9_rdir *rdir;
    struct v9fs_dirent *entry;

    /* P9_READDIRHDRSZ应该指的是P9消息头的长度
     */
    buflen = fid->clnt->p9_msize() - P9_READDIRHDRSZ;
    rdir = (struct p9_rdir *) malloc(sizeof(struct p9_rdir));

    while (1)
    {

        /* 2000, 2000.u使用p9_client_read, p9stat_read读取目录项
         */
        if (rdir->tail == rdir->head)
        {
            iov = {rdir->buf, (size_t) buflen};
            uio = {&iov, 1, pos, buflen, UIO_READ};
            
            n = p9_client::p9_client_read(fid, &uio, buflen, &err);
            if (err)
                return err;
            if (n == 0)
                return 0;

            rdir->head = 0;
            rdir->tail = n;
        }

        while (rdir->head < rdir->tail)
        {
            p9stat_init(&st);
            err = p9stat_read(fid->clnt, rdir->buf + rdir->head, 
                rdir->tail - rdir->head, &st);
            if (err) {
                debugf("V9FSl: p9stat_read returned %d\n", err);
                p9stat_free(&st);
                return -EIO;
            }
            reclen = st.size+2;

            /* 解析到一个目录项
             */
            entry = (struct v9fs_dirent *) malloc(sizeof(struct v9fs_dirent));
            entry->dirent.qid = st.qid;
            entry->dirent.d_off = pos + reclen;
            strcpy(entry->dirent.d_name, st.name);
            entry->dirent.d_type = dt_type(&st);
            entry->next = inode->entries;
            inode->entries = entry;

            p9stat_free(&st);

            rdir->head += reclen;
            pos = entry->dirent.d_off;
        }
    }
}

/* Load Children Entries of a directory
 * 2000.L加载目录的子目录项
 * [OK] 源于Linux内核
 */
static int load_dir_entries_dotl(struct v9fs_inode *inode)
{
    loff_t pos = 0;
    int err;
    int buflen;
    struct p9_fid *fid = inode->fid;
    struct p9_rdir *rdir;
    struct p9_dirent curdirent;
    struct v9fs_dirent *entry;

    /* P9_READDIRHDRSZ应该指的是P9消息头的长度
     */
    buflen = fid->clnt->p9_msize() - P9_READDIRHDRSZ;
    rdir = (struct p9_rdir *) malloc(sizeof(struct p9_rdir));

    while (1)
    {
        /* 2000.L使用p9_client_readdir读取目录项
         */
        if (rdir->tail == rdir->head)
        {
            err = p9_client::p9_client_readdir_dotl(fid, rdir->buf, buflen, pos);
            if (err <= 0)
                return err;

            rdir->head = 0;
            rdir->tail = err;
        }

        while (rdir->head < rdir->tail)
        {
            err = p9dirent_read(fid->clnt, rdir->buf + rdir->head, 
                rdir->tail - rdir->head, &curdirent);
            if (err < 0)
            {
                debugf("V9FS: p9dirent_read returned %d\n", err);
                return -EIO;
            }

            /* 解析到一个目录项
             */
            entry = (struct v9fs_dirent *) malloc(sizeof(struct v9fs_dirent));
            entry->dirent = curdirent;
            entry->next = inode->entries;
            inode->entries = entry;

            pos = curdirent.d_off;
            rdir->head += err;
        }
    }
}

/* Read the next item in a directory 
 * 读取目录的下一项,并更新f_offset
 * [Debug] 增删文件会影响readdir,暂时采取不感知方式
 */
static int v9fs_readdir(struct vnode *vp, struct file *fp, struct dirent *dir)
{
    int err;
    struct v9fs_inode *inode = (struct v9fs_inode *) vp->v_data;

    if (!inode->entries)
    {
        if (inode->handle_fid->clnt->p9_is_proto_dotl())
        {
            err = load_dir_entries_dotl(inode);
        }
        else
        {
            err = load_dir_entries(inode);
        }
        if (err)
        {
            debugf("V9FS: load_dir_entries[_dotl] failed %d\n", err);
        }
        inode->current = inode->entries;
    }

    if (inode->current)
    {
        dir->d_ino = v9fs_qid2ino(&inode->current->dirent.qid);
        dir->d_off = inode->current->dirent.d_off;
        // FIXME: not filling dir->d_reclen
        dir->d_type = inode->current->dirent.d_type;
        strlcpy((char *) &dir->d_name, inode->current->dirent.d_name, sizeof(dir->d_name));
        inode->current = inode->current->next;
        return 0;
    }

    return ENOENT;
}

/* Lookup a specific file in a directory
 * 查找目录下指定文件,构建新的vnode,填充{v_ino, v_type, v_mode, v_size, v_mount}
 * [OK]
 */
static int v9fs_lookup(struct vnode *dvp, char *name, struct vnode **vpp)
{
    struct p9_fid *fid;
    struct v9fs_inode *inode;
    std::string path = mkpath(dvp, name);
    struct vnode *vp;
    ino_t ino;

    // Make sure we don't accidentally return garbage.
    *vpp = nullptr;

    // Following 4 checks inspired by ZFS code
    if (!path.size())
        return ENOENT;

    if (dvp->v_type != VDIR)
        return ENOTDIR;

    assert(path != ".");
    assert(path != "..");

    /* 使用p9_client_walk获取文件的fid(处于未打开状态fid->mode = -1)
     */
    fid = p9_client::p9_client_walk(((struct v9fs_inode *) dvp->v_data)->fid, 
        1, (const unsigned char* const*) &name, 1);
    if (!fid) {
        return ENOENT; 
    }

    if (fid->clnt->p9_is_proto_dotl())
    {
         /* 2000.L使用p9_client_getattr_dotl
          */
        struct p9_stat_dotl *st = nullptr;
        st = p9_client::p9_client_getattr_dotl(fid, P9_STATS_BASIC);
        if (!st)
        {
            return -1;
        }
        ino = v9fs_qid2ino(&st->qid);
        // Create the new vnode or get it from the cache.
        if (vget(dvp->v_mount, ino, &vp)) {
            // Present in the cache
            *vpp = vp;
            return 0;
        }

        if (!vp) {
            return ENOMEM;
        }

        v9fs_set_vnode_dotl(vp, st);
    }
    else
    {
        /* 2000, 2000.u使用p9_client_stat
         */
        struct p9_wstat *st = nullptr;
        st = p9_client::p9_client_getattr(fid);
        if (!st)
        {
            return -1;
        }
        ino = v9fs_qid2ino(&st->qid);
        // Create the new vnode or get it from the cache.
        if (vget(dvp->v_mount, ino, &vp)) {
            // Present in the cache
            *vpp = vp;
            return 0;
        }

        if (!vp) {
            return ENOMEM;
        }

        v9fs_set_vnode(vp, st);
    }
    

    vp->v_mount = dvp->v_mount;
    inode = (struct v9fs_inode *) malloc(sizeof(struct v9fs_inode));
    memset(inode, 0, sizeof(struct v9fs_inode));
    inode->fid = fid;
    vp->v_data = inode;

    *vpp = vp;

    return 0;
}



/* Create a file
 * 创建文件(非目录,但可能是特殊文件)
 * [Debug] 创建文件会影响父目录readdir,如何处理, mode, perm, flag转换关系,
 *         如何解析rdev, extension
 */
static int v9fs_create(struct vnode *dvp, char *name, mode_t mode)
{
    int err;
    struct p9_fid *dfid = ((struct v9fs_inode *) dvp->v_data)->fid;
    struct p9_fid *fid;
    dev_t rdev;
    char extension[2 + U32_MAX_DIGITS + 1 + U32_MAX_DIGITS + 1];
    struct p9_qid qid;

    /* Parse rdev, extension
     */
    rdev = 0;
    if (S_ISBLK(mode))
    {
        sprintf(extension, "b %u %u", MAJOR(rdev), MINOR(rdev));
    }
    else if (S_ISCHR(mode))
    {
        sprintf(extension, "b %u %u", MAJOR(rdev), MINOR(rdev));
    }
    else
    {
        *extension = 0;
    }

    /* 复制一份父目录的fid,用于创建文件
     */
    fid = p9_client::p9_client_walk(dfid, 0, nullptr, 0);
    if (!fid)
    {
        err = -1;
        debugf("V9FS: p9_client_walk failed %d\n", err);
        return err;
    }

    if (fid->clnt->p9_is_proto_dotl())
    {
        /* 2000.L使用p9_client_create_dotl创建普通文件
         *       使用p9_client_mknod_dtol创建特殊文件
         */
        if (!strcmp(extension, ""))
        {
            /* flags仅使用P9_DOTL_CREATE进行单纯的文件创建,非使用额外的打开flags
             * gid使用无效值~0以使用默认值
             */
            err = p9_client::p9_client_fcreate_dotl(fid, name, 
                P9_DOTL_CREATE, mode, {(unsigned) ~0}, &qid);
            if (err < 0) {
                debugf("V9FS: p9_client_open_dotl failed %d\n", err);
            }
        }
        else
        {
            err = p9_client::p9_client_mknod_dotl(fid, name, 
                mode, rdev, {(unsigned) ~0}, &qid);
            if (err < 0) {
                debugf("V9FS: p9_client_mknod_dotl failed %d\n", err);
            }
        }  
    }
    else
    {
        /* 2000, 2000.u使用p9_client_fcreate
         */
        /* perm直接使用mode低32位
         * mode使用P9_OREAD进行最低的打开
         */
        err = p9_client::p9_client_fcreate(fid, name, 
            mode & ~0, P9_OREAD, extension);
        if (err < 0) {
            debugf("V9FS: p9_client_fcreate failed %d\n", err);
        }
    }

    /* 关闭复制的fid,
     * 虽然fid已指向新文件,依然可以关闭,因为之后会有VOP_LOOKUP重新找到这个文件
     */
    p9_client::p9_client_clunk(fid);
    /* 通知目录
     * readdir暂时不感知
     */

    return err;
}

/* Remove a file
 * 删除文件(非目录)
 * [Debug] 删除文件会影响父目录readdir,如何处理
 */
static int v9fs_remove(struct vnode *dvp, struct vnode *vp, char *name)
{
    int err = 0;
    struct p9_fid *dfid = ((struct v9fs_inode *) dvp->v_data)->fid;
    struct p9_fid *fid = ((struct v9fs_inode *) vp->v_data)->fid;

    /* 2000.L使用p9_client_unlinkat删除特殊文件
     *        使用p9_client_remove删除普通文件
     * 2000, 2000.u使用p9_client_remoe删除文件
     */
    if (fid->clnt->p9_is_proto_dotl() && 
        !p9_client::p9_client_unlinkat_dotl(dfid, name, P9_DOTL_AT_REMOVEDIR))
    {
        goto done;
    }

    err = p9_client::p9_client_remove(fid);
    if (err)
    {
        debugf("V9FS: p9_client_remove failed %d\n", err);
        return err;
    }

done:
    /* 通知目录
     * readdir暂时不感知
     */
    return err;
}

/* Rename a file
 * 重命名文件
 * [Debug] 操作加锁问题,重命名操作会影响源目录和目的目录,如何处理
 */
static int v9fs_rename(struct vnode *dvp1, struct vnode *vp1, char *name1,
                       struct vnode *dvp2, struct vnode *vp2, char *name2)
{
    int err;
    struct p9_fid *olddirfid, *newdirfid;
    struct p9_fid *oldfid;

    /* 为了避免影响源目录和目的目录,复制其fid
     */
    oldfid =((struct v9fs_inode *) vp1->v_data)->fid;
    if (!oldfid)
    {
        return -1;
    }

    olddirfid = p9_client::p9_client_walk(((struct v9fs_inode *) dvp1->v_data)->fid, 
        0, nullptr, 0);
    if (!olddirfid)
    {
        return -1;
    }

    newdirfid = p9_client::p9_client_walk(((struct v9fs_inode *) dvp2->v_data)->fid, 
        0, nullptr, 0);
    if (!newdirfid)
    {
        err = -1;
        goto clunk_olddir;
    }

    if (oldfid->clnt->p9_is_proto_dotl())
    {
        /* 2000.L使用p9_client_renameat或p9_client_rename
         */
        err = p9_client::p9_client_renameat_dotl(olddirfid, name1, newdirfid, name2);
        if (err == -EOPNOTSUPP)
        {
            err = p9_client::p9_client_rename(oldfid, newdirfid, name2);
        }
        if (err != -EOPNOTSUPP)
            goto clunk_newdir;
    }
    else
    {
        /* 2000, 2000.u使用p9_client_wstat
         */
        p9_wstat st;
        v9fs_blank_wstat(&st);
        st.muid = "nobody";
        st.name = name2;
        err = p9_client::p9_client_setattr(oldfid, &st);
        if (err)
        {
            debugf("V9FS: p9_client_wstat failed %d\n", err);
        }
    }

clunk_newdir:
    /* 通知源目录和目的目录
     * readdir暂时不感知
     */

    p9_client::p9_client_clunk(newdirfid);

clunk_olddir:
    p9_client::p9_client_clunk(olddirfid);

    return err;
}

/* Create a directory
 * 创建目录
 * [Debug] 创建目录会影响父目录readdir,如何处理, mode, perm, flag转换关系
 */
static int v9fs_mkdir(struct vnode *dvp, char *name, mode_t mode)
{
    int err;
    struct p9_fid *dfid = ((struct v9fs_inode *) dvp->v_data)->fid;
    struct p9_fid *fid;
    struct p9_qid qid;

    /* 复制一份父目录的fid,用于创建目录
     */
    fid = p9_client::p9_client_walk(dfid, 0, nullptr, 0);
    if (!fid)
    {
        err = -1;
        debugf("V9FS: p9_client_walk failed %d\n", err);
        return err;
    }

    if (dfid->clnt->p9_is_proto_dotl())
    {
        /* 2000.L使用p9_client_mkdir_dotl
         */
        err = p9_client::p9_client_mkdir_dotl(dfid, name, mode, {(unsigned) ~0}, &qid);
    }
    else
    {
        /* 2000, 2000.u使用p9_client_fcreate
         */
        err = p9_client::p9_client_fcreate(dfid, name, mode & ~0, P9_OREAD, nullptr);
    }

    /* 通知目录
     * readdir暂时不感知
     */

    return err;
}

/* Remove a directory
 * 删除目录
 * [Debug] 删除目录会影响父目录readdir,如何处理
 */
static int v9fs_rmdir(struct vnode *dvp, struct vnode *vp, char *name)
{
    int err;
    struct p9_fid *fid = ((struct v9fs_inode *) vp->v_data)->fid;

    err = p9_client::p9_client_remove(fid);
    if (err)
    {
        debugf("V9FS: p9_client_remove failed %d\n", err);
    }
    /* 通知目录
     * readdir暂时不感知
     */

    return err;
}

static inline struct timespec to_timespec(uint64_t sec, uint64_t nsec)
{
    struct timespec t;

    t.tv_sec = sec;
    t.tv_nsec = nsec;

    return t;
}

/* Inquire status of a file
 * 获取文件属性
 * [Debug] 属性转换
 */
static int v9fs_getattr(struct vnode *vp, struct vattr *attr)
{
    struct p9_fid *fid = ((struct v9fs_inode *)vp->v_data)->fid;

    if (fid->clnt->p9_is_proto_dotl())
    {
        /* 2000.L使用p9_client_getattr_dotl, p9_client_statfs
         */
        struct p9_stat_dotl *st;
        struct p9_rstatfs rs;
        st = p9_client::p9_client_getattr_dotl(fid, P9_STATS_ALL);
        if (!st)
            return -1;

        /* 填充attr
         */
        attr->va_mask    = st->st_result_mask;
        attr->va_type    = IFTOVT(st->st_mode & S_IFMT);
        attr->va_mode    = st->st_mode;
        attr->va_nlink   = st->st_nlink;
        attr->va_uid     = st->st_uid.val;
        attr->va_gid     = st->st_gid.val;
        
        if (!p9_client::p9_client_statfs(fid, &rs))
        {
            attr->va_fsid = rs.fsid;
        }
        attr->va_nodeid  = v9fs_qid2ino(&st->qid);
        attr->va_atime   = to_timespec(st->st_atime_sec, st->st_atime_nsec);
        attr->va_mtime   = to_timespec(st->st_mtime_sec, st->st_mtime_nsec);
        attr->va_ctime   = to_timespec(st->st_ctime_sec, st->st_ctime_nsec);
        attr->va_rdev    = st->st_rdev;
        attr->va_nblocks = st->st_blocks;
        attr->va_size    = st->st_size;
    }
    else
    {
        /* 2000, 2000.u使用p9_client_stat
         */
        struct p9_wstat *st;
        st = p9_client::p9_client_getattr(fid);
        if (!st)
            return -1;

        /* 填充attr
         */
        // attr->va_mask    = st->st_result_mask;
        attr->va_type    = IFTOVT(st->type & S_IFMT);
        attr->va_mode    = st->mode & ~S_IFMT;
        // attr->va_nlink   = ;
        if (fid->clnt->p9_is_proto_dotu())
        {
            attr->va_uid = st->n_uid.val;
            attr->va_gid = st->n_gid.val;
        }
        attr->va_fsid    = st->dev;
        attr->va_nodeid  = v9fs_qid2ino(&st->qid);
        attr->va_atime   = to_timespec(st->atime, 0);
        attr->va_mtime   = to_timespec(st->mtime, 0);
        // attr->va_ctime   = to_timespec(st->ctime, 0);
        // attr->va_rdev    = ;
        // attr->va_nblocks = ;
        attr->va_size    = st->size;
    }

    return 0;
}

/*
 * Attribute flags.
 */
#define P9_ATTR_MODE        (1 << 0)
#define P9_ATTR_UID     (1 << 1)
#define P9_ATTR_GID     (1 << 2)
#define P9_ATTR_SIZE        (1 << 3)
#define P9_ATTR_ATIME       (1 << 4)
#define P9_ATTR_MTIME       (1 << 5)
#define P9_ATTR_CTIME       (1 << 6)
#define P9_ATTR_ATIME_SET   (1 << 7)
#define P9_ATTR_MTIME_SET   (1 << 8)

/* Set status of a file
 * 设置文件属性,属性转换
 * [OK]
 */
static int v9fs_setattr(struct vnode *vp, struct vattr *attr)
{
    int err;
    struct p9_fid *fid = ((struct v9fs_inode *)vp->v_data)->fid;


    if (fid->clnt->p9_is_proto_dotl())
    {
        /* 2000.L使用p9_client_getattr
         */
        struct p9_iattr_dotl st;
        /* 填充st
         */
        st.valid = 0;
        if (attr->va_mode)
        {
            st.valid |= P9_ATTR_MODE;
            st.mode = attr->va_mode;
        }
        // st.uid        = attr->va_uid;
        // st.gid        = attr->va_gid;
        if (attr->va_size)
        {
            st.valid |= P9_ATTR_SIZE;
            st.size = attr->va_size;
        }
        if (attr->va_atime.tv_sec)
        {
            st.valid |= P9_ATTR_ATIME;
            st.atime_sec = attr->va_atime.tv_sec;
        }
        if (attr->va_atime.tv_nsec)
        {
            st.valid |= P9_ATTR_ATIME_SET;
            st.atime_nsec = attr->va_atime.tv_nsec;
        }
        if (attr->va_mtime.tv_sec)
        {
            st.valid |= P9_ATTR_MTIME;
            st.mtime_sec = attr->va_mtime.tv_sec;
        }
        if (attr->va_mtime.tv_nsec)
        {
            st.valid |= P9_ATTR_MTIME_SET;
            st.mtime_nsec = attr->va_mtime.tv_nsec;
        }
        
        err = p9_client::p9_client_setattr_dotl(fid, &st);
    }
    else
    {
        /* 2000, 2000.u使用p9_client_stat
         */
        struct p9_wstat st;
        /* 填充st
         */
        v9fs_blank_wstat(&st);
        st.mode = attr->va_mode;
        st.atime = attr->va_atime.tv_sec;
        st.mtime = attr->va_mtime.tv_sec;
        /* VFS没有修改uid, gid的操作
         */
        // if (p9_is_proto_dotu(fid->clnt))
        // {
        //     st.n_uid = attr->va_uid;
        //     st.n_gid = attr->va_gid;
        // }
        err = p9_client::p9_client_setattr(fid, &st);
    }

    if (err)
    {
        debugf("V9FS: setattr failed: %d\n", err);
    }

    return err;
}

/* Inactive a vnode, not a file
 * 失效vnode以便回收重用,关闭fid, handle_fid应该在close时已
 * [OK] 
 */
static int v9fs_inactive(vnode *vp)
{
    struct v9fs_inode *inode = (struct v9fs_inode *) vp->v_data;

    if (!inode)
        return -1;
    
    p9_client::p9_client_clunk(inode->fid);
    if (inode->handle_fid)
        p9_client::p9_client_clunk(inode->handle_fid);
    free(inode);
    vp->v_data = NULL;

    return 0;
}

/* Truncate a file
 * 调整文件大小
 * [Debug] 没有明显的原语,通过设置属性?
 */
static int v9fs_truncate(struct vnode *vp, off_t length)
{
    int err;
    struct p9_fid *fid = ((struct v9fs_inode *)vp->v_data)->fid;

    if (fid->clnt->p9_is_proto_dotl())
    {
        /* 2000.L使用p9_client_getattr
         */
        struct p9_iattr_dotl st;
        /* 填充st
         */
        st.valid = P9_ATTR_SIZE;
        st.size = length;

        err = p9_client::p9_client_setattr_dotl(fid, &st);
    }
    else
    {
        /* 2000, 2000.u使用p9_client_stat
         */
        struct p9_wstat st;
        /* 填充st
         */
        v9fs_blank_wstat(&st);
        st.size = length;
        err = p9_client::p9_client_setattr(fid, &st);
    }

    if (err)
    {
        debugf("V9FS: truncate failed: %d\n", err);
    }

    return 0;
}

/* Create a hard link
 * 创建硬连接
 * [OK]
 */
static int v9fs_link(struct vnode *ndvp, struct vnode *vp, char *name)
{
    int err;
    struct p9_fid *dfid = ((struct v9fs_inode *) ndvp->v_data)->fid;
    struct p9_fid *fid = ((struct v9fs_inode *) vp->v_data)->fid;
    struct p9_fid *odfid;

    if (fid->clnt->p9_is_proto_dotl())
    {
        /* 2000.L使用p9_client_link
         */
        err = p9_client::p9_client_link_dotl(dfid, fid, name);
    }
    else
    {
        /* 2000, 2000.u使用p9_client_fcreate
         * perm = P9_DMLINK
         * mode = P9_OREAD
         * extension = name
         */
        /* 复制一份父目录的fid,用于创建硬连接
         */
        odfid = p9_client::p9_client_walk(dfid, 0, nullptr, 0);
        if (!odfid)
        {
            err = -1;
            debugf("V9FS: p9_client_walk failed %d\n", err);
            return err;
        }
        err = p9_client::p9_client_fcreate(odfid, name, P9_DMLINK, 
            P9_OREAD, (char *) get_node_name(vp));
        p9_client::p9_client_clunk(odfid);
    }

    if (err)
    {
        debugf("V9FS: link failed: %d\n", err);
    }

    return err;
}

/* Cache file data
 * 缓存文件数据
 * [Debug] 暂不支持
 */
static int v9fs_arc(struct vnode *vp, struct file *fp, struct uio *uio)
{
    debugf("V9FS: Unsupported file operation: arc\n");

    return 0;
}

/* Allocate space for a file
 * 预留存储空间
 * [Debug] 暂不支持: 是否需要支持此操作,或者是否有可能支持此操作
 */
static int v9fs_fallocate(struct vnode *vp, int mode, loff_t off, loff_t len)
{
    debugf("V9FS: Unsupported file operation: fallocate\n");

    return 0;
}

#define PATH_MAX        4096    /* # chars in a path name including nul */

/* Read information of a link
 * 读取连接信息
 * [OK] 源于Linux内核
 */
static int v9fs_readlink(struct vnode *vp, struct uio *uio)
{
    int err;
    struct p9_fid *fid = ((struct v9fs_inode *) vp->v_data)->fid;
    char *target;
    struct p9_wstat *st;
    size_t sz;

    if (fid->clnt->p9_is_proto_dotl())
    {
        /* 2000.L使用p9_client_readlink
         */
        err = p9_client::p9_client_readlink_dotl(fid, &target);
        if (err)
        {
            debugf("V9FS: p9_client_readlink failed %d\n", err);
            return err;
        }
    }
    else
    {
        /* 2000不支持
         * 2000.u使用p9_client_stat
         */
        if (!(fid->clnt->p9_is_proto_dotu()))
        {
            debugf("V9FS: 2000 does not support readlink\n");
            return -EBADF;
        }
        st = p9_client::p9_client_getattr(fid);
        if (!st)
        {
            debugf("V9FS: p9_client_stat failed %d\n",  -1);
            return -1;
        }

        if (!(st->mode & P9_DMSYMLINK))
        {
            p9stat_free(st);
            free(st);
            return -EINVAL;
        }
        target = st->extension;
        st->extension = nullptr;
        if (strlen(target) >= PATH_MAX)
        {
            target[PATH_MAX - 1] = '\0';
        }

        p9stat_free(st);
        free(st);
    }

    sz = MIN(uio->uio_iov->iov_len, strlen(target) + 1);
    err = uiomove(target, sz, uio);
    free(target);

    return err;
}

/* Create a symbolic link
 * 创建软连接
 * [Debug] 参数顺序不确定
 */
static int v9fs_symlink(struct vnode *dvp, char *name, char *oldpath)
{
    int err;
    struct p9_fid *dfid = ((struct v9fs_inode *) dvp->v_data)->fid;
    struct p9_fid *odfid;
    struct p9_qid qid;

    if (dfid->clnt->p9_is_proto_dotl())
    {
        /* 2000.L使用p9_client_link
         */
        err = p9_client::p9_client_symlink_dotl(dfid, name, oldpath, 
            {(unsigned) ~0}, &qid);
    }
    else
    {
        /* 2000, 2000.u使用p9_client_fcreate
         * perm = P9_DMSYMLINK
         * mode = P9_OREAD
         * extension = name
         */
        /* 复制一份父目录的fid,用于创建软连接
         */
        odfid = p9_client::p9_client_walk(dfid, 0, nullptr, 0);
        if (!odfid)
        {
            err = -1;
            debugf("V9FS: p9_client_walk failed %d\n", err);
            return err;
        }
        err = p9_client::p9_client_fcreate(odfid, name, P9_DMSYMLINK, P9_OREAD, oldpath);
        p9_client::p9_client_clunk(odfid);
    }

    if (err)
    {
        debugf("V9FS: link failed: %d\n", err);
    }

    return err;
}

/*
 * vnode operations 
 */
struct vnops v9fs_vnops = {
    v9fs_open,               /* open */
    v9fs_close,              /* close */
    v9fs_read_with_cache,    /* read */
    v9fs_write,              /* write - returns error when called */
    v9fs_seek,               /* seek */
    v9fs_ioctl,              /* ioctl */
    v9fs_fsync,              /* fsync */
    v9fs_readdir,            /* readdir */
    v9fs_lookup,             /* lookup */
    v9fs_create,             /* create - returns error when called */
    v9fs_remove,             /* remove - returns error when called */
    v9fs_rename,             /* rename - returns error when called */
    v9fs_mkdir,              /* mkdir - returns error when called */
    v9fs_rmdir,              /* rmdir - returns error when called */
    v9fs_getattr,            /* getattr */
    v9fs_setattr,            /* setattr - returns error when called */
    v9fs_inactive,           /* inactive */
    v9fs_truncate,           /* truncate - returns error when called*/
    v9fs_link,               /* link - returns error when called*/
    v9fs_arc,                /* arc */ //TODO: Implement to allow memory re-use when mapping files
    v9fs_fallocate,          /* fallocate - returns error when called*/
    v9fs_readlink,           /* read link */
    v9fs_symlink             /* symbolic link - returns error when called*/
};