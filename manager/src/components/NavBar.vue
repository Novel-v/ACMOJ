<!--
   Copyright 2020-2021 the original author or authors.

   Licensed under the General Public License, Version 3.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

        https://www.gnu.org/licenses/gpl-3.0.en.html
 -->

<template>
  <div>
    <Row>
      <div class="logo" @click="$router.push('/')">
        <img src="../assets/Logo.jpg" style="width: 150px; height: 80px;"/>
      </div>
    </Row>
    <Menu :active-name="$route.path.split('/')[1]" width="auto">
      <MenuItem name="user" :to="{ name: 'user' }">
        <Icon type="ios-navigate"></Icon>
        User
      </MenuItem>
      <MenuItem name="problem" :to="{ name: 'problem' }">
        <Icon type="ios-navigate"></Icon>
        Problem
      </MenuItem>
      <MenuItem name="contest" :to="{ name: 'contest' }">
        <Icon type="ios-keypad"></Icon>
        Contest
      </MenuItem>
      <MenuItem name="template" :to="{ name: 'template' }">
        <Icon type="ios-paper"></Icon>
        Judge Template
      </MenuItem>
<!--      <MenuItem name="group" :to="{ name: 'group' }">-->
<!--        <Icon type="ios-contacts"></Icon>-->
<!--        Group-->
<!--      </MenuItem>-->
    </Menu>
  </div>
</template>

<script>
// 引入api和mapGetters
import api from '@/utils/api';
import { mapGetters } from 'vuex';

export default {
  computed: {
    // 使用 mapGetters 辅助函数将 store 中的 getter 映射到局部计算属性
    ...mapGetters('user', ['username'])
  },
  mounted: function () {
    // 获取用户信息
    api.getProfile();
  }
};
</script>

<style lang="less" scoped>
  /* 改变Menu组件的背景颜色 */
  .ivu-menu-light {
    background-color: #e7e3e3; //与@layout-sider-background 一致
  }

  .logo {
    display: flex;/* 设置为flex布局 */
    justify-content: center; /* 水平居中 */
    align-items: center; /* 垂直居中 */
    margin: 16px 0 16px 24px; /* 设置的外边距 */

    :hover {
      cursor: pointer;/* 鼠标移动到上面时显示手型 */
    }
  }

  /deep/ .ivu-menu-vertical {
    line-height: 45px;/* 设置菜单项的行高 */
  }
</style>
