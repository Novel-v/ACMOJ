/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the General Public License, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.gnu.org/licenses/gpl-3.0.en.html
 */

import Vue from 'vue';
import axios from 'axios';
import store from '@/store';

axios.defaults.baseURL = `${process.env.VUE_APP_OJ_SERVER}/api`;
axios.defaults.withCredentials = true;

function post(url, data, options) {
  // 如果没有传入data参数，则将data设置为空对象
  data = data || {};
  // 如果没有传入options参数，则将options设置为空对象
  options = options || {};
  // 返回一个新的Promise对象
  return new Promise((resolve, reject) => {
    // 使用axios发送POST请求
    axios.post(url, data, options)
      .then(response => {
        // 检查响应头的content-type是否不包含'application/json'
        if (response.headers['content-type'].indexOf('application/json') === -1) {
          // 如果不是JSON，则直接resolve响应对象
          resolve(response);
        } else if (response.data.code === 0) {
          // 如果响应数据的code为0，表示请求成功
          resolve(response.data.data);
        } else {
          // 如果响应数据的code不为0，表示请求失败，显示错误信息
          Vue.prototype.$Message.error(response.data.message);
          // 并reject响应数据
          reject(response.data);
        }
      }, err => {
        // 如果请求失败，结束加载动画
        Vue.prototype.$Loading.finish();
        // 并reject错误响应数据
        reject(err.response.data);
      })
  });
}

function get(url, params, options) {
  // 如果没有传入params参数，则将params设置为空对象
  params = params || {};
  // 如果没有传入options参数，则将options设置为空对象
  options = options || {};
  // 返回一个新的Promise对象
  return new Promise((resolve, reject) => {
    // 使用axios发送GET请求
    axios.get(url, { params, options })
      .then(response => {
        // 如果响应数据的code为0，表示请求成功
        if (response.data.code === 0) {
          // resolve响应数据的data部分
          resolve(response.data.data);
        } else {
          // 如果响应数据的code不为0，表示请求失败，显示错误信息
          Vue.prototype.$Message.error(response.data.message);
          // 并reject响应数据
          reject(response.data);
        }
      }, err => {
        // 如果请求失败，结束加载动画
        Vue.prototype.$Loading.finish();
        // 并reject错误响应数据
        reject(err.response.data);
      })
  })
}

export default {
  // 配置相关
  getCopyright: function() {
    // 调用get函数，发送GET请求到'/site/getCopyright'，并返回Promise对象
    return get('/site/getCopyright');
  },

  // ---------------------- 用户相关 ----------------------
  getProfile: function (success, error) {
    // 使用axios发送GET请求到'/user/getProfile'
    axios.get('/user/getProfile')
      .then(response => {
        // 如果响应数据的code为0，表示请求成功
        if (response.data.code === 0) {
          // 通过Vuex的store分发'action'，将响应数据存储到store中
          store.dispatch('user/setProfile', response.data.data);
          // 如果传入了success回调函数，则调用它并传入响应数据
          if (success) {
            success(response.data.data);
          }
        } else {
          // 如果响应数据的code不为0，表示请求失败，显示错误信息
          Vue.prototype.$Message.error(response.data.message);
        }
      }, err => {
        // 如果请求失败，且错误状态码为401（未授权）
        if (err.response.status === 401) {
          // 通过Vuex的store分发'action'，清除用户信息
          store.dispatch('user/clearProfile');
          // 如果传入了error回调函数，则调用它并传入错误响应数据
          if (error) {
            error(err.response.data);
          }
        }
      });
  },
  // 查询用户列表
  getUserList: function (params) {
    return get('/manage/user/list', params);
  },
  // 更改用户信息
  updateUserInfo: function (data) {
    return post('/manage/user/update', data);
  },
  // 更改用户密码
  updateUserPasswd: function (data) {
    return post('/manage/user/update', data);
  },
  // 批量添加用户
  addUsers: function (data) {
    return post('/manage/user/addUsers', data);
  },
  // 删除用户
  deleteUsers: function (data) {
    return post('/manage/user/delete', data);
  },
  // ---------------------- 题目相关 ----------------------
  // 查询题目列表
  getProblemList: function (params) {
    return get('/manage/problem/list', params);
  },
  // 查询题目
  getProblem: function (params) {
    return get('/manage/problem/query', params);
  },
  // 更新题目信息
  updateProblemInfo: function (data) {
    return post('/manage/problem/update', data);
  },
  // 创建题目
  createProblem: function (data) {
    return post('/manage/problem/create', data);
  },
  // ---------------------- 题面相关 ----------------------
  // 查询题目的描述列表
  getProblemDescriptionList: function (params) {
    return get('/manage/problem/queryDescriptionList', params);
  },
  // 查询题目描述
  getProblemDescription: function (params) {
    return get('/manage/problem/queryDescription', params);
  },
  // 更新题面描述
  updateDescription: function (data) {
    return post('/manage/problem/updateDescription', data);
  },
  // 创建新题面描述
  createDescription: function (data) {
    return post('/manage/problem/createDescription', data);
  },
  deleteDescription: function(params) {
    return get('/manage/problem/deleteDescription', params);
  },
  // ---------------------- 测试点相关 ----------------------
  // checkpoint单点上传
  uploadSingleCheckpoint: function (data) {
    return post('/manage/checkpoint/upload', data);
  },
  // checkpoint批量上传
  uploadCheckpointFiles: function (data) {
    return post('/manage/checkpoint/uploadFiles', data);
  },
  // 获取题目的checkpoint列表
  getCheckpointList: function (problemCode) {
    return get('/manage/checkpoint/list', { problemCode });
  },
  // 获取checkpoint详情
  getCheckpointPreview: function (checkpointId) {
    return get('/manage/checkpoint/query', { checkpointId });
  },
  // 全量更新题目的checkpoint
  updateProblemCheckpoints: function (data) {
    return post('/manage/problem/update', data);
  },
  // ---------------------- 比赛相关 ----------------------
  // 获取比赛列表
  getContestList: function (params) {
    return get('/manage/contest/page', params);
  },
  // 获取单个比赛详情
  getContest: function (params) {
    return get('/manage/contest/query', params);
  },
  // 更新比赛信息
  updateContest: function (data) {
    return post('/manage/contest/update', data);
  },
  // 创建比赛
  createContest: function (data) {
    return post('/manage/contest/create', data);
  },
  // ----------------- 评测模板相关 -------------------
  // 查询单个评测模板
  getOneTemplate: function(id) {
    return get('/manage/judgetemplate/query', { id });
  },
  // 查询多页评测模板
  getTemplateList: function(params) {
    return get('/manage/judgetemplate/page', params);
  },
  // 创建评测模板
  createTemplate: function(data) {
    return post('/manage/judgetemplate/create', data);
  },
  // 更新评测模板
  updateTemplate: function(data) {
    return post('/manage/judgetemplate/update', data);
  },
  // 评测模板title右模糊匹配
  queryTemplateTitle: function(title) {
    return get('/manage/judgetemplate/listByTitle', { title });
  },
  // ----------------- 评测模板相关 -------------------
  // 单文件上传
  singleUpload: function(data) {
    return post('/filesys/upload', data);
  },
  // 多文件上传
  multiUpload: function(data) {
    return post('/filesys/uploadFiles', data);
  },
  // 用 md5 查文件
  checkMD5: function(md5) {
    return get('/filesys/queryByMd5', { md5 });
  },
  // 以zip包下载多个文件
  zipDownload: function(data) {
    return new Promise((resolve, reject) => {
      post('filesys/zipDownload', data, { responseType: 'blob' }).then(ret => {
        resolve(ret);
        const blob = new Blob([ret.data], { type: ret.headers['content-type'] });
        const elink = document.createElement('a');
        const filename = new Date().getTime().toString();
        if ('download' in elink) {
          elink.download = filename;
          elink.href = URL.createObjectURL(blob);
          elink.click();
          URL.revokeObjectURL(elink.href);
        } else {
          navigator.msSaveBlob(blob, filename);
        }
      }, err => (reject(err)));
    })
  },
  /* ************ group ****************** */
  createGroup: function (data) {
    return post('/manage/group/create', data);
  },
  updateGroup: function (data) {
    return post('/manage/group/update', data);
  },
  getGroupDetail: function (params) {
    return get('/manage/group/query', params);
  },
  getGroupList: function (params) {
    return get('/manage/group/page', params);
  },
  updateUserStatus: function (data) {
    return post('/manage/group/updateUserStatus', data);
  },
  addUsersToGroup: function (data) {
    return post('/manage/group/addUser', data);
  },
  deleteGroup: function (params) {
    return get('/manage/group/delete', params);
  },
  queryGroupTitle: function (params) {
    return get('/manage/group/listByTitle', params);
  }
}
