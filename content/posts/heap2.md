---
title: "Everything In Its Right Place: Pt 2"
summary: "Exploring Memory allocation, vulnerabilities, and exploitation"
date: 2024-06-27T14:35:11-04:00
author: hyp
draft: false
---

# Everything In Its Right Place: Pt 2

In the last article in this series, I created a simple version of malloc/free and demonstrated a heap overflow vulnerability. In this next article, I decided to add bins to my implementation and demonstrate a fast bin attack.

# What is a bin?

Bins, also known as free lists, are arrays of freed memory chunks. Bins allow us to reallocate chunks of memory more quickly and efficiently. In our previous implementation, the entire list of allocated chunks had to be enumerated in order to determine if a free chunk that fit the size requirements was available to be reused. Bins only store freed chunks, and are arranged by size, which makes the search and selection process much faster.

To get a better understanding of bins, let’s take a look at the GLIBC implementation of malloc (ptmalloc2). ptmalloc2 utilizes 5 different types of bins; fast, unsorted, small, large, and tcache. Fast and small bins are similar in the sense that each of the corresponding bins stores a chunk of a fixed size. This means that each fast and small bin will automatically be sorted which makes the process of adding and removing chunks from the bins fast. The main difference between fast and small bins is that coalescence does not take place for chunks stored in fast bins, whereas chunks stored in small bins can be merged with adjacent freed chunks, which helps reduce memory fragmentation. I won’t go into detail about the other type of bins as it is not necessary for our simple implementation, but for more information check out this article: [https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)

# Bins in mmalloc()

For this implementation, we are going to create an array for fast bins as well as a single sorted bin. There will be a total of 8 fast bins, corresponding to the following sizes: 8, 16, 24, 32, 40, 48, 56, 64. For all **mmalloc()** requests, we will round the size up to the nearest multiple of 8. This will ensure that for any request lower than or equal to 64, there is a corresponding fast bin that it can be added to. The 8 byte alignment will also come in handy when we add the capability to coalesce chunks, but that will be discussed in a future article.

The sorted bin will handle any chunks that have a size greater than 64, and will be sorted from smallest to largest. Sorting the chunks in this manner will allow **mmalloc()** to easily return the smallest freed chunk that fits the requested size.

To allow for easy sorting in the sorted bin, we are going to adjust the header to allow for a doubly linked list. I decided to replicate the header structure of GLIBC’s malloc to achieve this. This adjusted header structure will also come into play when discussing the fastbin attack. Let’s take a look at the previous header compared to the adjusted one.

![](/images/1__8NzRaZ6Y7BgLdzElrtgEQ.png)

As we can see, the new header includes a field for forward (**fd**) and back (**bk**). These two fields are similar to the **next** field in the old header as they contain pointers to the previous and next chunk in their corresponding bin of freed chunks. The **size** field is the same as the previous header in the fact that it defines the size of the useable memory in the chunk, excluding the size of the header itself. One big difference between the old header and the new is how the header is treated differently based on whether a chunk is in use or free. When the chunk is in use, the useable memory actually starts directly after the **size** field. This allows us to save space that would otherwise be taken up by the unused **fd** and **bk** fields.

![](/images/1_yDuu7EvIAJFht-OzCXpbaA.png)

Once a chunk has been freed, the **fd** and **bk** fields are filled in accordingly. This behavior differs depending on whether the freed chunk is destined for the sorted bin or a fast bin. Since the chunks that get stored in fast bins are of a fixed size, there is no need to sort them and therefore no need to create a doubly linked list. For speed purposes, we will store newly freed chunks destined for the fast bins as a singly linked list by only setting the **fd** pointer and just remove chunks from the top of this list as we reuse them.

![](/images/1_vHDIqh-6W3wPgV_OCx5IBQ.png)

Let’s take a look at how this all looks in code, starting with our new chunk header structure and the creation of our bins.

```
struct chunk_data {  
    size_t prev_size;  
    size_t size;    struct chunk_data *fd;  
    struct chunk_data *bk;  
};
typedef struct chunk_data *binptr;
binptr sortedbins = NULL;  
binptr fastbins[NFASTBINS] = {NULL};
```

Here we can see the adjustments made to our header to include the **prev_size**, **fd**, and **bk** fields and remove the unused **free**, **magic**, and **next** fields. We then create our sorted bin and array of fast bins and initialize their values to NULL.

To see how chunks get added to these bins, we can take a look at the source for **mfree()**.

```
struct chunk_data *ptr = get_chunk_ptr(chunk);if(ptr->size <= 64) {  
    fastbin_add(ptr);  
} else {  
    sortbin_add(ptr);  
}
```

**mfree()** makes a call to **get_chunk_ptr()** to get the address in memory that points to the start of the chunk header, then evaluates its size to determine if the chunk should be stored in the sorted bin or one of the fast bins. If the chunk is destined for a fast bin, then **fastbin_add()** is called which evaluates whether or not the corresponding bin is already populated. If it is, then the **fd** pointer of the new chunk is set to the first member of the fast bin, and the fast bin head is set to the address of the new chunk. This effectively adds the new chunk to the top of the bin.

```
if(fastbins[FASTBIN_IDX(chunk->size)]) {  
    chunk->fd = fastbins[FASTBIN_IDX(chunk->size)];  
    fastbins[FASTBIN_IDX(chunk->size)] = chunk;  
} else {  
    fastbins[FASTBIN_IDX(chunk->size)] = chunk;  
    chunk->fd = NULL;  
}
```

The **FASTBIN_IDX(x)** macro shown in the previous source is used to easily find the proper fast bin index that corresponds to the requested chunk size (i.e — a chunk size of 64 would correspond to the 8th index in this array) and is declared as follows:

```
#define FASTBIN_IDX(x) ((x+7) >> 3) - 1
```

The process for adding a chunk to the sorted bin is a bit more involved. Essentially the sorted bin is first checked to see if it has been populated or not. If it is not populated, then the chunk is simply set to the head of the list and the **fd** and **bk** pointers are both set to NULL.

```
} else {  
    sortedbins = chunk;  
    chunk->bk = NULL;  
    chunk->fd = NULL;  
}
```

If the sorted bin has already been populated, then we enumerate through the list of freed chunks, checking the size. Once an entry is found that is greater than or equal to the size requested, the **bk** pointer of that chunk is evaluated to determine if the current chunk is at the head of the list or not.

```
while(current) {  
        last = current->bk;        
        if((current->size >= chunk->size) && !(current->bk)) {  
            chunk->bk = NULL;  
            chunk->fd = current;  
            current->bk = chunk;            
            sortedbins = chunk;            
            return 0;  
        } else if((current->size >= chunk->size) && current->bk) {            
            chunk->bk = last;  
            chunk->fd = current;  
            current->bk = chunk;  
            last->fd = chunk;            
            return 0;  
        }        
        last = current;  
        current = current->fd;  
}
```

If **!(current->bk)** is evaluated as true, we can infer that the current chunk is indeed the head. At this point the chunk that is being added to the bin gets its **bk** pointer set to NULL, its **fd** pointer set to the current chunk and the **bk** pointer of the current chunk is set to the newly added chunk. This effectively adds the new chunk to the head of the list.

if the second if condition evaluates as true, we can infer that the new chunk is being added somewhere in the middle of the list. In this case, our strategy is very similar to the previous one with the exception that we are setting the **bk** pointer of the new chunk and the **fd** pointer of the last chunk in the list.

If both if statements evaluate as false, then the chunk needs to be added to the end of the list, which is done like so.

```
last->fd = chunk;  
chunk->bk = last;  
chunk->fd = NULL;
```

Now that we have an idea of how chunks get added to their respective bins, let’s take a look at how chunks are selected for reuse when **mmalloc()** is called.

```
if(fastbins[FASTBIN_IDX(aligned_size)]) {  
    chunk = reuse_fastchunk(FASTBIN_IDX(aligned_size));
} else if(sortedbins) {  
    chunk = reuse_chunk(sortedbins, aligned_size);  
}if(!chunk) {  
    chunk = req_space(aligned_size);    if(!chunk) {  
        return NULL;  
    }  
}
```

Here we can see that the corresponding fast bin index is evaluated to see if it is populated. If it is, then the **reuse_fastchunk()** function is called to remove the chunk from the bin and return it for **mmalloc()**’s use. Looking at the source of **reuse_fastchunk()** we can see that it sets a **chunk_data** pointer current to the head of the corresponding fast bin, then evaluates if the **fd** pointer is populated. If it is, the head of the fast bin is set to that pointer, otherwise it is set to NULL which marks the list as empty.

```
struct chunk_data *reuse_fastchunk(size_t size) {  
    if(fastbins[size]) {  
        struct chunk_data *current = fastbins[size];  
          
        if(current->fd) {  
            fastbins[size] = current->fd;  
        } else {  
            fastbins[size] = NULL;  
        }  
        return current;  
    }  
    return NULL;  
}
```

If the corresponding fast bin is empty, or the requested chunk size is too large to fit into a fast bin, then the sorted bin is checked to see if it is populated. If this bin is populated, then **reuse_chunk()** is called with the pointer to the sorted bin as its first argument and the requested size as its second argument. The **reuse_chunk()** function then proceeds to enumerate through the chunks in the provided bin until it finds one that can satisfy the request or runs into the end of the list.

```
while(current && !(current->size >= size)) {  
    current = current->fd;  
}
if(current) {  
    struct chunk_data *last = current->bk;    if(last && current->fd) {   
        //If true, chunk is in middle of list  
          
        last->fd = current->fd;  
        current->fd->bk = last;  
    } else if(!(last) && current->fd) {   
        //If true, chunk is at the start of list  
          
        *bin = current->fd;  
        current->bk = NULL;  
    } else if(current && !(current->fd && current->bk)) {  
        //If true, chunk is only member of list  
          
        last->fd = NULL;  
    } else {  
        //If true, chunk is at the end of the list  
          
        *bin = NULL;  
    }  
}
```

If a chunk that fits the size is found, then it is evaluated against a number of conditions to determine where it stands in the list. (warning this code is ugly and should be rewritten). I will not go into too much detail regarding this function as the vulnerability we will demonstrate is specific to the fast bin implementation, but I have included some comments in the above code for anyone who is curious.

# Fastbin Attack

Ok, so now that we have a good idea of how our bins are being populated and used to reissue chunks, let’s talk about how we can use a use-after-free vulnerability to exploit an issue with the fast bin implementation.

A use-after-free vulnerability occurs when memory is mismanaged in a way that allows an attacker to reference an area of memory that has already been freed. Similar to the heap overflow demonstrated in the previous article, we can use this vulnerability to overwrite the **fd** pointer in the freed chunk to corrupt the free list and provide the attacker with a write-anything-anywhere primitive.

Let’s take a look at how this works exactly. If we remember the description of the fast bins earlier, we know that each chunk is added and removed from the top a fast bin (LIFO) based on size. As each fast list grows, the **fd** pointer of the newest chunk is pointed to the previous head of the list. As the chunks in the fast bin are used and the list shrinks, the first chunk in the list is removed and the following chunk becomes the head. So to take advantage of this behavior, we need to be able to write to a freed chunk that is somewhere above the bottom of the list, and we need to be able to allocate enough chunks of matching size until we are provided with a chunk that lives at the corrupted address we provided when we wrote to the previously mentioned freed chunk. At this point, we need to be able to make a write to the last allocated chunk to complete the attack.

To get a better idea of how this works, let’s create a scenario where this specific behavior takes place. First we will reuse the jump table that we used in the previous article as our target.

```
print_func *jmp_table[2] = {  
    good_print,  
    bad_print  
};
```

Next we will allocated three chunks of the same size, then free those three chunks.

```
test = mmalloc(16);  
test2 = mmalloc(16);  
test3 = mmalloc(16);mfree(test);  
mfree(test2);  
mfree(test3);
```

At this point, our fast bin for size 16 should have three chunks, the memory allocated for test3, followed by test2, followed by test. Next we will make a write to the chunk at the head of the list, which as mentioned is test3.

```
strcpy(test3, "\x20\xe4\xff\xff\xff\x7f");
```

In this instance, the address that is being written to test3 is the area of the stack that contains the pointer to **good_print()** in our jump table. It is important to remember the structure of a freed chunk to understand how this part works.

![](/images/1_yDuu7EvIAJFht-OzCXpbaA.png)

Taking a look at the difference between the freed chunk and the allocated chunk, we can see that the area that we are writing to is the exact area that contains the **fd** pointer of a freed chunk. So by writing a memory address to that pointer, we are essentially redirecting the fast bin to point to an arbitrary area of memory that we will be able to control.

Now that we have corrupted the **fd** pointer of the first chunk in this fast bin, we want to allocate two more chunks of the same size. The first chunk that is allocated can be discarded, but the second chunk will be pointed to the overwritten address. At this point we can copy the address of the **bad_print()** function to this area of memory which will overwrite the function pointer that is currently stored there (**good_print**) and we can make a call to that jump table entry as follows.

```
test4 = mmalloc(16);  
functest = mmalloc(16);  
strcpy(functest, "\xcf\x59\x55\x55\x55\x55");
jmp_table[0]();
```

# Wrap-up

Hopefully this article provides a good basic understanding of how bins work and how we can leverage a vulnerability to corrupt header data of chunks that live in those bins. I came across so many great resources while writing this and just wanted to share some of them here.

[https://0x00sec.org/t/heap-exploitation-fastbin-attack/3627](https://0x00sec.org/t/heap-exploitation-fastbin-attack/3627)

[https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)

[https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bins_chunks](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bins_chunks)

[https://sourceware.org/glibc/wiki/MallocInternals](https://sourceware.org/glibc/wiki/MallocInternals)

[https://developers.redhat.com/blog/2017/03/02/malloc-internals-and-you#tunings](https://developers.redhat.com/blog/2017/03/02/malloc-internals-and-you#tunings)

[https://6point6.co.uk/insights/common-software-vulnerabilities-part-ii-explaining-the-use-after-free/](https://6point6.co.uk/insights/common-software-vulnerabilities-part-ii-explaining-the-use-after-free/)

[https://github.com/shellphish/how2heap](https://github.com/shellphish/how2heap)
