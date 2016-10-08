#ifndef BUFFER_H
#define BUFFER_H

#include <condition_variable>
#include <mutex>
#include <queue>

using std::queue;
using std::mutex;
using std::lock_guard;
using std::unique_lock;
using std::condition_variable;

template<typename Element>
class Buffer
{
	queue<Element> elems;
	mutex mut;
	condition_variable cv;
	
public:
	void offer(Element e)
	{
		lock_guard<mutex> lock(mut);
		elems.push(e);
		cv.notify_one();
	}
	
	Element take()
	{
		unique_lock<mutex> lock(mut);
		while (elems.empty())
		{
			cv.wait(lock);
		}
		return elems.pop();
	}
};

#endif