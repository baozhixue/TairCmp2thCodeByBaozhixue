#include "NvmEngine.hpp"

// 根据key进行hash返回一个32位的ID用作索引
uint32_t key_hash_engine(const char *data)
{
    return ((uint64_t *)data)[0] % UINT32_MAX;
}

uint64_t bucketID_hash_engine(const char *data)
{
    return (((uint64_t *)data)[1]) & Bucket::BUCKET_MASK;
}

namespace HashIndex
{
    void Node::set_val(uint64_t pmem_offset)
    {
        *(uint64_t *)(this->val) = pmem_offset;
    }
    uint64_t Node::get_val()
    {
        return *(uint64_t *)(this->val);
    }
    int Node::is_equal(const char *tuple_key, uint32_t node_key, char *pmem_address_base)
    {
        if (this->nkey == UINT32_MAX)
        {
            return -1; // 此处node节点为空
        }
        if (this->nkey == node_key)
        {
            Tuple::Tuple *left = (Tuple::Tuple *)(pmem_address_base + this->get_val());
            if (left->is_equal(tuple_key) == true)
            {
                return 0; // 相等
            }
        }
        return 1; // 不相等
    }
    int Node::is_equal(Node &right)
    {
        if (this->nkey == UINT32_MAX)
        {
            return -1;
        }
        if (this->nkey == right.nkey && this->get_val() == right.get_val())
        {
            return 0;
        }
        return 1;
    }
    void Hash::init(char *pmem_base_address)
    {
        this->max_size_ = HASH_INIT_SIZE;
        this->expand_limit_size_ = this->expand_flag_ * this->max_size_;
        this->nodes_ = new Node[this->max_size_];
        this->pmem_base_address_ = pmem_base_address;
    }

    /*
        若[tuple_key,node_key]已存在，则返回旧值(pmem_offset)
    */
    char *Hash::insert(const char *tuple_key, const char *tuple_pmem_address, uint32_t node_key)
    {
        if (this->cur_size_ > this->expand_limit_size_)
        {
            this->expand();
        }
        return this->insert(tuple_key, tuple_pmem_address, node_key, this->max_size_);
    }
    Node *Hash::find(const char *tuple_key, uint32_t node_key)
    {
        Node *ret_node = nullptr;

        uint32_t idx = this->hash_node_key(node_key, this->max_size_);
        uint32_t counter = 0;
        while (counter < this->max_size_)
        {
            int ret = this->nodes_[idx].is_equal(tuple_key, node_key, this->pmem_base_address_);
            if (ret == 0)
            {
                // 相等
                ret_node = this->nodes_ + idx;
                break;
            }
            else if (ret == -1)
            {
                // 此处无有效值
                break;
            }
            ++counter;
            ++idx;
            idx %= this->max_size_;
        }

        return ret_node;
    }
    uint32_t Hash::hash_node_key(uint32_t node_key, uint32_t mask)
    {
        return node_key % mask;
    }
    char *Hash::insert(const char *tuple_key, const char *tuple_pmem_address, uint32_t node_key, uint32_t mask)
    {
        uint32_t idx = this->hash_node_key(node_key, mask);
        uint32_t counter = 0;
        char *ret_ptr = nullptr;
        while (counter < mask)
        {
            int ret = this->nodes_[idx].is_equal(tuple_key, node_key, this->pmem_base_address_);
            if (ret == -1)
            {
                this->nodes_[idx].nkey = node_key;
                this->nodes_[idx].set_val(tuple_pmem_address - this->pmem_base_address_);
                this->cur_size_ += 1;
                break;
            }
            else if (ret == 0)
            {
                ret_ptr = (this->pmem_base_address_ + this->nodes_[idx].get_val());
                this->nodes_[idx].set_val(tuple_pmem_address - this->pmem_base_address_);
                break;
            }
            ++idx;
            idx %= mask;
            ++counter;
        }

        return ret_ptr;
    }
    void Hash::expand_insert(Node &node, uint32_t mask, Node *nodes)
    {
        uint32_t idx = this->hash_node_key(node.nkey, mask);
        uint32_t counter = 0;
        while (counter < mask)
        {
            if (nodes[idx].nkey == UINT32_MAX)
            {
                nodes[idx] = node;
                break;
            }
            ++counter;
            ++idx;
            idx %= mask;
        }
    }
    void Hash::expand()
    {
        uint32_t tmp_max_size = this->max_size_ * expand_factor_;
        Node *tmp_nodes = new Node[tmp_max_size];
        for (size_t i = 0; i < this->max_size_; ++i)
        {
            if (this->nodes_[i].nkey != UINT32_MAX)
            {
                this->expand_insert(this->nodes_[i], tmp_max_size, tmp_nodes);
            }
        }
        delete[] this->nodes_;
        this->nodes_ = tmp_nodes;
        this->max_size_ = tmp_max_size;
        this->expand_limit_size_ = this->max_size_ * this->expand_flag_;
    }
} // namespace HashIndex

namespace Manager
{

    void PageHeader::clear()
    {
        this->page = nullptr;
        this->del_pos.clear();
        this->level = 0;
        this->cur_data_offset = 0;
        this->block_nums = 0;
        this->pinfo.bucket_id = 0;
        this->pinfo.page_id = 0;
    }
    Tuple::Tuple *PageHeader::alloc_tuple(uint16_t tuple_len)
    {
        Tuple::Tuple *ret = (Tuple::Tuple *)(this->page->data + this->cur_data_offset);
        this->cur_data_offset += tuple_len;
        return ret;
    }
    void Page::clear()
    {
#ifdef PMEM_VERSION
        pmem_memset_persist(this, 0, PMEM_PAGE_SIZE);
#else
        memset(this, 0, PMEM_PAGE_SIZE);
#endif // LOCAL_VERSION
    }

    Page *ManagerV2::alloc_free_page(size_t bid) {
        size_t level = bid/BUCKET_LEVEL_RANGE;
        Page *page = nullptr;
        for(size_t i=0;i<LEVEL_SIZE && page== nullptr;++i){

            this->muts_[level].lock();
            if(this->pages_[level].size()>0){
                page = this->pages_[level].back();
                this->pages_[level].pop_back();
                this->size_.fetch_sub(1);
            }
            this->muts_[level].unlock();
            ++level;
            level%=LEVEL_SIZE;
        }
        return page;
    }

    void ManagerV2::recycle_free_page(Page* page,size_t gpid){
        size_t  level = gpid/PAGE_LEVEL_RANGE;
        this->muts_[level].lock();
        this->pages_[level].push_back(page);
        this->size_.fetch_add(1);
        this->muts_[level].unlock();
    }

    Page *ManagerV2::alloc_mem_buf_page() {
        this->mem_buf_mut_.lock();
        Page *ret = this->mem_buf_pages_.back();
        this->mem_buf_pages_.pop_back();
        this->mem_buf_mut_.unlock();
        return ret;
    }

    void ManagerV2::recycle_mem_page(Page *page) {
        this->mem_buf_mut_.lock();
        this->mem_buf_pages_.push_back(page);
        this->mem_buf_mut_.unlock();
    }

    size_t ManagerV2::size() const noexcept{
        return this->size_;
    }

} // namespace Manager

namespace Bucket
{
    void Bucket::init(char *pmem_base_address, Manager::ManagerV2 *manager, GargabeCollector::GargabeCollector *gc, uint32_t id)
    {
        this->ID = id;
        this->pmem_base_address_ = pmem_base_address;
        this->manager_ = manager;
        this->hash.init(this->pmem_base_address_);
        this->gc_ = gc;
#ifdef LINUX_PLATFORM
        pthread_rwlock_init(&(this->hash_rwlock_), nullptr);
#endif
    }

    Status Bucket::push(const char *key, const char *value, uint16_t val_len, uint32_t hash_node_key)
    {

        Tuple::Tuple mem_tuple(key, value, val_len); // 初始化数据

        Tuple::Tuple *pmem_tuple = this->pmem_tuple_alloc(mem_tuple.tuple_len()); // 开始写入

        // 无锁写回数据
#ifdef PMEM_VERSION
        pmem_memcpy_persist(pmem_tuple, &mem_tuple, mem_tuple.tuple_len());
#else
        memcpy(pmem_tuple, &mem_tuple, mem_tuple.tuple_len());
#endif // LOCAL_VERSION

        // 更新索引信息
#ifdef LINUX_PLATFORM
        pthread_rwlock_wrlock(&(this->hash_rwlock_));
#else
        this->hash_mut_.lock();
#endif

        Tuple::Tuple *del_pmem_tuple=(Tuple::Tuple *)this->hash.insert(mem_tuple.key(), (char *)pmem_tuple, hash_node_key);
        if(del_pmem_tuple!=nullptr){
            this->push_tuple_block((char*)del_pmem_tuple,del_pmem_tuple->tuple_len());
        }
#ifdef LINUX_PLATFORM
        pthread_rwlock_unlock(&(this->hash_rwlock_));
#else
        this->hash_mut_.unlock();
#endif
        // 索引更新完成

        this->insert_counter.fetch_sub(1); // 写入完成

        return Status::Ok;
    }

    Status Bucket::find(const char *key, std::string *value, uint32_t hash_node_key)
    {
        // 更新索引信息
#ifdef LINUX_PLATFORM
        pthread_rwlock_rdlock(&(this->hash_rwlock_));
#else
        this->hash_mut_.lock();
#endif
        Status status = Status::NotFound;

        HashIndex::Node *node = this->hash.find(key, hash_node_key);
        if (node != nullptr)
        {
            Tuple::Tuple *pmem_tuple = (Tuple::Tuple *)(this->pmem_base_address_ + node->get_val());
            value->assign(pmem_tuple->value(), pmem_tuple->value_len());
            status = Status::Ok;
        }
        // 更新索引信息
#ifdef LINUX_PLATFORM
        pthread_rwlock_unlock(&(this->hash_rwlock_));
#else
        this->hash_mut_.unlock();
#endif
        return status;
    }

    Tuple::Tuple *Bucket::pmem_tuple_alloc(const size_t &alloc_len)
    {
        std::lock_guard<std::mutex> lck(this->pmem_tuple_alloc_mut_);
        this->insert_counter.fetch_add(1);
        return (Tuple::Tuple *)this->pmem_alloc(alloc_len);
    }

    char *Bucket::pmem_alloc(const size_t &alloc_len)
    {
        if (this->cur_page == nullptr ||
            this->cur_page->cur_data_offset + alloc_len > Manager::PMEM_PAGE_DATA_SIZE)
        {
            Manager::Page *page = this->manager_->alloc_free_page(this->ID - 1);
            size_t gpid = ((char *)page - this->pmem_base_address_) / Manager::PMEM_PAGE_SIZE;
            this->cur_page = &(Manager::global_page_header_register[gpid].pheader);
            this->cur_page->page = page;
            this->cur_page->block_nums = 0;
            this->cur_page->cur_data_offset = 0;
            this->cur_page->level = 0;
            this->cur_page->pinfo.bucket_id = this->ID;
            this->cur_page->pinfo.page_id = this->cur_page_id;
            this->cur_page->del_pos.reserve((1 << 16));
            this->cur_page_id += 1;

#ifdef PMEM_VERSION
            pmem_memcpy_persist((char *)&(this->cur_page->page->info), (char *)&(this->cur_page->pinfo), sizeof(Manager::PageInfo));
#else
            memcpy((char *)&(this->cur_page->page->info), (char *)&(this->cur_page->pinfo), sizeof(Manager::PageInfo));
#endif // LOCAL_VERSION

            this->gc_->page_register(this->cur_page);
        }
        char *ret = this->cur_page->page->data + this->cur_page->cur_data_offset;
        this->cur_page->cur_data_offset += alloc_len;
        return ret;
    }

    void Bucket::recovery(Manager::Page *page)
    {
        if (page == nullptr)
        {
            // 以page_id 排序,若有冲突数据，则page_id最大的页具有最新数据
            std::sort(this->pages_.begin(), this->pages_.end(),
                      [](const Manager::PageHeader *left, const Manager::PageHeader *right) { return left->pinfo.page_id < right->pinfo.page_id; });
            for (auto pheader : this->pages_)
            {

                Tuple::Tuple *iter = (Tuple::Tuple *)pheader->page->data;
                while (pheader->cur_data_offset < Manager::PMEM_PAGE_DATA_SIZE)
                {
                    int ret = iter->is_valid();
                    int check_ret = iter->data_check(); // 若此值显示当前tuple无效，则后续无数据
                    if (ret == 1 && check_ret == 0)
                    { // 有效tuple
                        uint32_t node_key = key_hash_engine(iter->key());
                        Tuple::Tuple *tmp = (Tuple::Tuple *)this->hash.insert(iter->key(), (char *)iter, node_key);
                        if (tmp != nullptr)
                        { // 检测到重复tuple，删除旧值
                            tmp->set_invalid();
                            this->push_tuple_block((char *)tmp, tmp->tuple_len());
                        }
                    }
                    else if (ret == 0 && check_ret == 0)
                    { // 已删除tuple
                        this->push_tuple_block((char *)iter, iter->tuple_len());
                    }
                    else
                    { // 页遍历结束
                        break;
                    }
                    pheader->cur_data_offset += iter->tuple_len();
                    iter = (Tuple::Tuple *)(pheader->page->data + pheader->cur_data_offset);
                }
            }
            this->pages_.clear();
        }
        else
        {
            Manager::PageHeader *pheader = new Manager::PageHeader;
            pheader->page = page;
            pheader->pinfo = page->info;
            this->pages_.push_back(pheader);
            this->cur_page_id = std::max(this->cur_page_id, page->info.page_id + 1);
        }
    }

    bool Bucket::defragmentation(Manager::PageHeader *pheader)
    {

        this->pmem_tuple_alloc_mut_.lock(); // 对顶层锁上锁

        while (this->insert_counter>0)
        {
            // 轮询直至在调用此函数前的所有插入完成
            // 此时索引信息，pheader内del_pos信息保证是一致的
        }

        if (pheader == this->cur_page)
        {
            this->cur_page = nullptr;
        }

        // 对索引加锁，避免find函数返回错误数据
#ifdef LINUX_PLATFORM
        pthread_rwlock_wrlock(&(this->hash_rwlock_));
#else
        this->hash_mut_.lock();
#endif

        if (pheader->cur_data_offset > pheader->block_nums)
        {
            Manager::Page *mem_page = this->manager_->alloc_mem_buf_page();
            memcpy(mem_page, pheader->page, Manager::PMEM_PAGE_SIZE);

            Tuple::Tuple *tuple_iter = nullptr;

            for (auto &pos : pheader->del_pos)
            {
                tuple_iter = (Tuple::Tuple *)(mem_page->data + pos);
                tuple_iter->set_invalid();
            }

            tuple_iter = (Tuple::Tuple *)(mem_page->data);
            uint64_t offset = 0;
            while (offset < pheader->cur_data_offset)
            {
                int ret = tuple_iter->is_valid();
                if (ret == 1)
                {
                    uint32_t node_key = key_hash_engine(tuple_iter->key());
                    Tuple::Tuple *pmem_tuple = (Tuple::Tuple*)this->pmem_alloc(tuple_iter->tuple_len());
// 无锁写回数据
#ifdef PMEM_VERSION
                    pmem_memcpy_persist(pmem_tuple, tuple_iter, tuple_iter->tuple_len());
#else
                    memcpy(pmem_tuple, tuple_iter, tuple_iter->tuple_len());
#endif // LOCAL_VERSION

                    this->hash.insert(tuple_iter->key(),(char*)pmem_tuple,node_key);
                }
                else if (ret == -1)
                {
                    break;
                }
                offset += tuple_iter->tuple_len();
                tuple_iter = (Tuple::Tuple *)(mem_page->data + offset);
            }
            this->manager_->recycle_mem_page(mem_page);
        }

#ifdef LINUX_PLATFORM
        pthread_rwlock_unlock(&(this->hash_rwlock_));
#else
        this->hash_mut_.unlock();
#endif

        //pheader->page->clear();
        Manager::Page *page = pheader->page;
        pheader->clear(); // 只清除pheader内描述信息，page内容不做清空
        page->clear();
        this->manager_->recycle_free_page(page,pheader->gpid);  // gpid is not edited by anything

        this->pmem_tuple_alloc_mut_.unlock(); // 对顶层锁解锁

        return true;
    }


    void Bucket::push_tuple_block(char *tuple_address, uint16_t tuple_len)
    {
        uint64_t offset = tuple_address - this->pmem_base_address_;
        Manager::PageHeader *pheader = &(Manager::global_page_header_register[offset / Manager::PMEM_PAGE_SIZE].pheader);

        pheader->block_nums += tuple_len;
        size_t old_level = pheader->level;
        pheader->level = pheader->block_nums / GargabeCollector::PER_LEVEL_PAGE_SIZE;
        pheader->del_pos.push_back(tuple_address - pheader->page->data);

        if (pheader->level > old_level)
        {
            this->gc_->page_advance(pheader, old_level);
        }
    }

} // namespace Bucket

namespace GargabeCollector
{
    void GargabeCollector::init()
    {
        this->levels_ = new Level[PAGE_MAX_LEVEL + 1];
        this->mut_ = new std::mutex[PAGE_MAX_LEVEL + 1];
    }
    void GargabeCollector::page_register(Manager::PageHeader *pheader)
    {
        std::lock_guard<std::mutex> lck(this->mut_[0]);
        this->levels_[0][pheader->page] = pheader;
    }

    void GargabeCollector::page_register(Manager::PageHeader *pheader, size_t level)
    {
        std::lock_guard<std::mutex> lck(this->mut_[level]);
        this->levels_[level][pheader->page] = pheader;
    }

    void GargabeCollector::page_advance(Manager::PageHeader *pheader, size_t old_level)
    {
        {
            std::lock_guard<std::mutex> lck(this->mut_[old_level]);
            this->levels_[old_level].erase(pheader->page);
        }
        {
            std::lock_guard<std::mutex> lck(this->mut_[old_level + 1]);
            this->levels_[old_level + 1][pheader->page] = pheader;
        }
    }

    size_t GargabeCollector::size()
    {
        return (this->levels_[PAGE_MAX_LEVEL].size() + this->levels_[PAGE_MAX_LEVEL - 1].size()) / 8;
    }

    Manager::PageHeader *GargabeCollector::get_page()
    {
        Manager::PageHeader *ret = nullptr;
        for (size_t i = 0; i < PAGE_MAX_LEVEL; ++i)
        {
            size_t pos = PAGE_MAX_LEVEL - i;
            {
                std::lock_guard<std::mutex> lck(this->mut_[pos]);
                auto iter = this->levels_[pos].begin();
                if (iter != this->levels_[pos].end())
                {
                    ret = iter->second;
                    this->levels_[pos].erase(ret->page);
                    break;
                }
            }
        }
        return ret;
    }

} // namespace GargabeCollector

Status NvmEngine::CreateOrOpen(const std::string &name, DB **dbptr, FILE *log_file)
{
    NvmEngine *db = new NvmEngine(name, log_file);
    *dbptr = db;
    return Status::Ok;
}

NvmEngine::NvmEngine(const std::string &name, FILE *log_file)
{
#ifdef LOCAL_VERSION
    this->mem_ptr_ = (char *)mmap(NULL, PMEM_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, 0, 0);
#else
    this->mem_ptr_ = (char *)pmem_map_file(name.c_str(), PMEM_MAX_SIZE,
                                           PMEM_FILE_CREATE, 0666,
                                           &this->mapped_len_, &this->is_pmem_);
#endif // LOCAL_VERSION

    Manager::global_page_header_register = new Manager::Page2PHeader[Manager::PMEM_PAGE_NUM];
    for(size_t i=0;i<Manager::PMEM_PAGE_NUM;++i){
        Manager::global_page_header_register[i].pheader.gpid = i;
    }


    this->manager_ = new Manager::ManagerV2;

    this->gc_ = new GargabeCollector::GargabeCollector;
    this->gc_->init();

    Manager::Page *buf_page = new Manager::Page[16]; // thread num
    for (size_t i = 0; i < 16; ++i)
    {
        this->manager_->recycle_mem_page(buf_page+i);
    }

    this->buckets_ = new Bucket::Bucket[Bucket::BUCKET_MAX_SIZE];
    for (size_t i = 0; i < Bucket::BUCKET_MAX_SIZE; ++i)
    {
        this->buckets_[i].init(this->mem_ptr_, this->manager_, this->gc_, i + 1);
    }

    this->log_file_ = log_file;

    Manager::Page *page_iter = (Manager::Page *)this->mem_ptr_;
    const size_t page_num = PMEM_MAX_SIZE / sizeof(Manager::Page);
    size_t i = 0;
    while (i < page_num)
    {
        if (page_iter->info.bucket_id == 0) // 未分配
        {
            this->manager_->recycle_free_page(page_iter,i);
        }
        else
        {
            this->buckets_[page_iter->info.bucket_id - 1].recovery(page_iter); // bucket 从1排序
        }
        ++page_iter;
        ++i;
    }

    for (size_t i = 0; i < Bucket::BUCKET_MAX_SIZE; ++i)
    {
        this->buckets_[i].recovery(nullptr); // 传入nullptr开始整理数据，建立索引
    }

#ifdef PRINT_LOG
    this->time_counter = time(nullptr);
#endif // PRINT_LOG
}

Status NvmEngine::Get(const Slice &key, std::string *value)
{
    uint64_t bid = bucketID_hash_engine(key.data());
    uint32_t hash_key = key_hash_engine(key.data());
    return this->buckets_[bid].find(key.data(), value, hash_key);
}

Status NvmEngine::Set(const Slice &key, const Slice &value)
{

    if (this->manager_->size() < Manager::GLOBA_PAGE_WARNING)
    {

        for (size_t i = 0; i < 8; ++i)
        {
            Manager::PageHeader *pheader = this->gc_->get_page();
            if (pheader != nullptr)
            {
                if (this->buckets_[pheader->pinfo.bucket_id - 1].defragmentation(pheader) == false)
                {
                    this->gc_->page_register(pheader, pheader->level);
                }
            }
        }
    }

    uint64_t bid = bucketID_hash_engine(key.data());
    uint32_t hash_key = key_hash_engine(key.data());

    this->buckets_[bid].push(key.data(), value.data(), value.size(), hash_key);

#ifdef PRINT_LOG

    this->write_len += (key.size() + value.size() + sizeof(Tuple::Tuple));
    this->insert_data_counter_ += 1;

    if (this->log_file_ != nullptr && this->insert_data_counter_ % 100000 == 1)
    {
        fprintf(this->log_file_, "insert data %lld , write len %lld, spend time %lld, Page warning %lld, tuple block %lld ,race rate %lld \n",
                this->insert_data_counter_, this->write_len, time(nullptr) - this->time_counter, this->manager_->size(), Bucket::tuple_block_counter.load(), this->race_counter);
        fflush(this->log_file_);
    }

    if (this->insert_data_counter_ > 1024 * 1024 * 16 * 24)
    {
        exit(-1);
    }

#endif // PRINT_LOG
    return Status::Ok;
}

NvmEngine::~NvmEngine()
{
}

Status DB::CreateOrOpen(const std::string &name, DB **dbptr, FILE *log_file)
{
    return NvmEngine::CreateOrOpen(name, dbptr, log_file);
}

DB::~DB() {}