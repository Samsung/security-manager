/*
 * Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        popup_service_callbacks.cpp
 * @author      Lukasz Wrzosek (l.wrzosek@samsung.com)
 * @version     1.0
 * @brief       Header of Security Caller class used by services socket callbacks
 */

#ifndef SECURITY_CALLER_H__
#define SECURITY_CALLER_H__

#include <dpl/thread.h>
#include <dpl/assert.h>
#include <dpl/singleton.h>

#include <security_controller.h>

#include <pthread.h>

class IEventHolder
{
 public:
  virtual void FinalizeSending() = 0;
  virtual ~IEventHolder() {};
};

template<class EventType>
class EventHolderImpl : public IEventHolder
{
  EventType event;

 public:
  EventHolderImpl(const EventType& e) : event(e) {}
  virtual void FinalizeSending()
  {
    LogDebug("sending real sync event");
    CONTROLLER_POST_SYNC_EVENT(SecurityController, event);
  }
};

/*
 * Because Security Controller is a DPL::Controler class, its events
 * can be send only from a DPL managed thread. SecurityCallerTread class
 * has been implemented as a workaround of that constraint.
 * This class is a DPL managed thread that waits for requests
 * from non DPL managed threads and when receives one it posts event
 * to the Security Controler in charge of the calling thread.
 */


class SecurityCallerThread : public DPL::Thread
{
 private:
  pthread_mutex_t m_mutex2;
  pthread_mutex_t m_mutex;
  pthread_cond_t m_cond;
  pthread_cond_t m_cond2;
  bool m_continue;
  bool m_finished;
  IEventHolder* m_eventHolder;
  pthread_mutex_t m_syncMutex;


  SecurityCallerThread() :
    Thread(),
    m_mutex2(PTHREAD_MUTEX_INITIALIZER),
    m_mutex(PTHREAD_MUTEX_INITIALIZER),
    m_cond(PTHREAD_COND_INITIALIZER),
    m_cond2(PTHREAD_COND_INITIALIZER),
    m_continue(true),
    m_finished(false),
    m_eventHolder(NULL),
    m_syncMutex(PTHREAD_MUTEX_INITIALIZER)
  {
    LogDebug("constructor");
  }

  virtual ~SecurityCallerThread()
  {
    pthread_mutex_unlock(&m_syncMutex);
    pthread_cond_destroy(&m_cond);
    pthread_cond_destroy(&m_cond2);
    pthread_mutex_destroy(&m_mutex2);
    pthread_mutex_destroy(&m_mutex);
    pthread_mutex_destroy(&m_syncMutex);
  }

 protected:
  /* main routine of the SecurityCallerThread */
  virtual int ThreadEntry()
  {
    LogDebug("SecurityCallerThread start");
    pthread_mutex_lock(&m_mutex); // lock shared data

    while (m_continue) // main loop
    {
      if (m_eventHolder) // if m_eventHolder is set, the request has been received
      {
        m_eventHolder->FinalizeSending(); // send actual event in charge of calling thread
        delete m_eventHolder;
        m_eventHolder = NULL;
        LogDebug("setting finished state");
        pthread_mutex_lock(&m_syncMutex); // lock m_finished
        m_finished = true;
        pthread_mutex_unlock(&m_syncMutex); // unlock m_finished
        LogDebug("finished");
        pthread_cond_signal(&m_cond2); // signal a calling thread that event has been posted.
      }
      LogDebug("waiting for event");
      // atomically:
      // unlock m_mutex, wait on m_cond until signal received, lock m_mutex
      pthread_cond_wait(&m_cond, &m_mutex);
      LogDebug("found an event");
    }

    pthread_mutex_unlock(&m_mutex);

    return 0;
  }

 public:
  void Quit()
  {
    LogDebug("Quit called");
    pthread_mutex_lock(&m_mutex);    // lock shared data
    m_continue = false;              // main loop condition set to false
    pthread_mutex_unlock(&m_mutex);  // unlock shard data
    pthread_cond_signal(&m_cond);
  }

  template <class EventType>
  void SendSyncEvent(const EventType& event)
  {
    // prevent SendSyncEvent being called by multiple threads at the same time.
    pthread_mutex_lock(&m_mutex2);
    LogDebug("sending sync event");
    bool correct_thread = false;
    Try {
      LogDebug("Checking if this is unmanaged thread");
      DPL::Thread::GetCurrentThread();
    } Catch (DPL::Thread::Exception::UnmanagedThread) {
      correct_thread = true;
    }
    Assert(correct_thread &&
           "This method may not be called from DPL managed thread or main thread");
    LogDebug("putting an event to be posted");
    pthread_mutex_lock(&m_mutex);  // lock shared data
    Assert(m_eventHolder == NULL && "Whooops");
    m_eventHolder = new EventHolderImpl<EventType>(event); // put an event to be posted
    pthread_mutex_unlock(&m_mutex); // unlock shared data
    LogDebug("Signal caller thread that new event has been created");
    pthread_cond_signal(&m_cond);   // signal SecurityCallerThread to wake up because new
                                    // event is waiting to be posted

    LogDebug("waiting untill send completes");
    pthread_mutex_lock(&m_syncMutex); /* wait until send completes */
    while (!m_finished)
    {
        pthread_cond_wait(&m_cond2, &m_syncMutex); // wait until event is posted
    }
    LogDebug("done");
    m_finished = false;
    pthread_mutex_unlock(&m_syncMutex);
    pthread_mutex_unlock(&m_mutex2);
  }

 private:
  friend class DPL::Singleton<SecurityCallerThread>;
};

typedef DPL::Singleton<SecurityCallerThread> SecurityCallerSingleton;



#endif //SECURITY_CALLER_H__
